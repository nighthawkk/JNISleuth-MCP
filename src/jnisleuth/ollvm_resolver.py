"""Automated ARM64 OLLVM Indirect-Branch (BR Xn / CSEL / Jump-Table) Resolver & ELF Patcher."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
import struct
from typing import Any

from .elf_scanner import ElfBinary

ARM64_COND_NAMES: dict[int, str] = {
    0x0: "EQ",
    0x1: "NE",
    0x2: "CS",
    0x3: "CC",
    0x4: "MI",
    0x5: "PL",
    0x6: "VS",
    0x7: "VC",
    0x8: "HI",
    0x9: "LS",
    0xA: "GE",
    0xB: "LT",
    0xC: "GT",
    0xD: "LE",
    0xE: "AL",
    0xF: "NV",
}

ARM64_NOP = 0xD503201F


@dataclass
class ResolvedIndirectBranch:
    """Represents a resolved ARM64 indirect branch (`BR Xn` or `BLR Xn`) in an OLLVM state machine."""

    site_va: int
    site_offset: int
    branch_reg: str
    mnemonic: str
    pattern_type: str
    condition: str | None
    state_register: str | None
    compared_state_id: int | None
    target_vas: list[int] = field(default_factory=list)
    csel_va: int | None = None
    patch_preview_asm: list[str] = field(default_factory=list)
    patched_bytes_hex: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "site_va": f"0x{self.site_va:06x}",
            "site_offset": f"0x{self.site_offset:06x}",
            "branch_reg": self.branch_reg,
            "mnemonic": self.mnemonic,
            "pattern_type": self.pattern_type,
            "condition": self.condition,
            "state_register": self.state_register,
            "compared_state_id": (
                f"0x{self.compared_state_id:08x}" if self.compared_state_id is not None else None
            ),
            "target_vas": [f"0x{va:06x}" for va in self.target_vas],
            "csel_va": f"0x{self.csel_va:06x}" if self.csel_va is not None else None,
            "patch_preview_asm": self.patch_preview_asm,
            "patched_bytes_hex": self.patched_bytes_hex,
        }


@dataclass
class OLLVMStateTransition:
    """Represents a state transition discovered in an OLLVM flattened `JNI_OnLoad` dispatcher."""

    state_id: int
    block_va: int
    block_offset: int
    next_state_ids: list[int] = field(default_factory=list)
    calls_register_natives: bool = False
    description: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "state_id": f"0x{self.state_id:08x}",
            "block_va": f"0x{self.block_va:06x}",
            "block_offset": f"0x{self.block_offset:06x}",
            "next_state_ids": [f"0x{s:08x}" for s in self.next_state_ids],
            "calls_register_natives": self.calls_register_natives,
            "description": self.description,
        }


def encode_arm64_b(pc: int, target_va: int) -> int:
    """Encodes an unconditional ARM64 `B <target_va>` instruction."""
    imm26 = ((target_va - pc) // 4) & 0x03FFFFFF
    return 0x14000000 | imm26


def encode_arm64_b_cond(pc: int, target_va: int, cond: int) -> int:
    """Encodes a conditional ARM64 `B.<cond> <target_va>` instruction."""
    imm19 = ((target_va - pc) // 4) & 0x7FFFF
    return 0x54000000 | (imm19 << 5) | (cond & 0xF)


def _sign_extend(val: int, bits: int) -> int:
    sign_bit = 1 << (bits - 1)
    return (val & (sign_bit - 1)) - (val & sign_bit)


def resolve_ollvm_indirect_branches(
    elf: ElfBinary,
    fn_offset: int = 0x005200,
    max_scan_bytes: int = 0x0800,
) -> dict[str, Any]:
    """Statically resolves OLLVM `CSEL` + `BR Xn` and jump-table indirect branches in `JNI_OnLoad`."""
    if elf.arch_abi != "arm64-v8a":
        return {
            "so_name": elf.name,
            "arch": elf.arch_abi,
            "fn_offset": f"0x{fn_offset:06x}",
            "indirect_branch_count": 0,
            "indirect_branches": [],
            "state_transitions": [],
        }

    fn_va = elf.offset_to_va(fn_offset)
    end_off = min(len(elf.data), fn_offset + max_scan_bytes)
    code = elf.data[fn_offset:end_off]

    # Track symbolic/concrete register states across the function
    reg_const: dict[int, int] = {}
    adrp_page: dict[int, int] = {}
    reg_jump_table_targets: dict[int, list[int]] = {}
    csel_info: dict[int, dict[str, Any]] = {}

    last_cmp_reg: int | None = None
    last_cmp_val: int | None = None

    resolved_branches: list[ResolvedIndirectBranch] = []
    state_transitions: list[OLLVMStateTransition] = []
    seen_states: dict[int, OLLVMStateTransition] = {}
    current_block_va = fn_va
    current_state_id: int | None = None

    for rel_off in range(0, len(code) - 3, 4):
        insn = struct.unpack_from("<I", code, rel_off)[0]
        pc = fn_va + rel_off
        file_off = fn_offset + rel_off

        # 1. Decode ADR Xd, #imm21 (op=0, bit 31=0, bits [28:24]=10000)
        if (insn & 0x9F000000) == 0x10000000:
            rd = insn & 0x1F
            immlo = (insn >> 29) & 0x3
            immhi = (insn >> 5) & 0x7FFFF
            imm21 = _sign_extend((immhi << 2) | immlo, 21)
            reg_const[rd] = pc + imm21
            reg_jump_table_targets.pop(rd, None)

        # 2. Decode ADRP Xd, #page (op=1, bit 31=1, bits [28:24]=10000)
        elif (insn & 0x9F000000) == 0x90000000:
            rd = insn & 0x1F
            immlo = (insn >> 29) & 0x3
            immhi = (insn >> 5) & 0x7FFFF
            imm21 = _sign_extend((immhi << 2) | immlo, 21)
            page_va = (pc & ~0xFFF) + (imm21 << 12)
            adrp_page[rd] = page_va
            reg_const[rd] = page_va

        # 3. Decode ADD Xd, Xn, #imm12 (64-bit: 0x91000000)
        elif (insn & 0xFF800000) == 0x91000000:
            rd = insn & 0x1F
            rn = (insn >> 5) & 0x1F
            imm12 = (insn >> 10) & 0xFFF
            sh = (insn >> 22) & 0x1
            if sh:
                imm12 <<= 12
            if rn in adrp_page:
                reg_const[rd] = adrp_page[rn] + imm12
            elif rn in reg_const:
                reg_const[rd] = reg_const[rn] + imm12

        # 4. Decode MOVZ / MOVK (32-bit and 64-bit: bits [28:23] == 0b100101)
        elif ((insn >> 23) & 0x3F) == 0x25:
            rd = insn & 0x1F
            imm16 = (insn >> 5) & 0xFFFF
            hw = (insn >> 21) & 0x3
            opc = (insn >> 29) & 0x3
            shift = hw * 16
            if opc == 2:  # MOVZ
                reg_const[rd] = imm16 << shift
            elif opc == 3:  # MOVK
                prev = reg_const.get(rd, 0)
                mask = ~(0xFFFF << shift) & 0xFFFFFFFFFFFFFFFF
                reg_const[rd] = (prev & mask) | (imm16 << shift)

        # 5. Decode MOV Xd, Xm (ORR Xd, XZR, Xm: 0xAA0003E0) or MOV Wd, Wm (0x2A0003E0)
        elif (insn & 0x7FE0FFE0) == 0x2A0003E0 and ((insn >> 5) & 0x1F) == 31:
            rd = insn & 0x1F
            rm = (insn >> 16) & 0x1F
            if rm in reg_const:
                reg_const[rd] = reg_const[rm]
            if rm in csel_info:
                csel_info[rd] = dict(csel_info[rm])
            if rm in reg_jump_table_targets:
                reg_jump_table_targets[rd] = list(reg_jump_table_targets[rm])

        # 6. Decode CMP Wn/Xn, #imm12 (SUBS XZR/WZR, Rn, #imm12: 0x7100001F / 0xF100001F)
        elif (insn & 0x7F80001F) == 0x7100001F:
            rn = (insn >> 5) & 0x1F
            imm12 = (insn >> 10) & 0xFFF
            sh = (insn >> 22) & 0x1
            if sh:
                imm12 <<= 12
            last_cmp_reg = rn
            last_cmp_val = imm12
            current_state_id = imm12

        # 7. Decode CMP Wn/Xn, Wm/Xm (SUBS XZR/WZR, Rn, Rm: 0x6B00001F / 0xEB00001F)
        elif (insn & 0x7FE0001F) == 0x6B00001F:
            rn = (insn >> 5) & 0x1F
            rm = (insn >> 16) & 0x1F
            last_cmp_reg = rn
            if rm in reg_const:
                last_cmp_val = reg_const[rm] & 0xFFFFFFFF
                current_state_id = last_cmp_val

        # 8. Decode CSEL Xd, Xn, Xm, cond (64-bit: 0x9A800000 mask 0xFFE00C00)
        elif (insn & 0xFFE00C00) == 0x9A800000:
            rd = insn & 0x1F
            rn = (insn >> 5) & 0x1F
            cond = (insn >> 12) & 0xF
            rm = (insn >> 16) & 0x1F
            true_va = reg_const.get(rn)
            false_va = reg_const.get(rm)
            targets: list[int] = []
            if true_va is not None and elf.is_executable_va(true_va):
                targets.append(true_va)
            if false_va is not None and elf.is_executable_va(false_va) and false_va not in targets:
                targets.append(false_va)
            csel_info[rd] = {
                "csel_va": pc,
                "csel_offset": file_off,
                "rn": rn,
                "rm": rm,
                "cond": cond,
                "cond_name": ARM64_COND_NAMES.get(cond, "AL"),
                "true_va": true_va,
                "false_va": false_va,
                "targets": targets,
                "state_reg": f"W{last_cmp_reg}" if last_cmp_reg is not None else None,
                "state_id": last_cmp_val,
            }

        # 9. Decode LDR Xt, [Xn, Xm, LSL #3] (Jump-table indexed load: 0xF8607800 mask 0xFFE0FC00)
        #    or LDR Xt, [Xn, #imm] where Xn points to a jump table in .rodata / .data.rel.ro
        elif (insn & 0xFFE0FC00) == 0xF8607800 or (insn & 0xFFC00000) == 0xF9400000:
            rt = insn & 0x1F
            rn = (insn >> 5) & 0x1F
            base_ptr = reg_const.get(rn)
            if base_ptr is not None and not elf.is_executable_va(base_ptr):
                tbl_off = elf.va_to_offset(base_ptr)
                if tbl_off is not None and tbl_off + 8 <= len(elf.data):
                    jt_targets: list[int] = []
                    for entry_i in range(16):
                        ptr_val = elf.read_pointer_at(tbl_off + entry_i * 8, base_ptr + entry_i * 8)
                        if ptr_val and elf.is_executable_va(ptr_val):
                            if ptr_val not in jt_targets:
                                jt_targets.append(ptr_val)
                        else:
                            break
                    if jt_targets:
                        reg_jump_table_targets[rt] = jt_targets
                        csel_info.pop(rt, None)

        # 10. Detect RegisterNatives vtable load (+0x6b8) inside a state block
        if (insn & 0xFFC00000) == 0xF9400000:
            imm_bytes = ((insn >> 10) & 0xFFF) * 8
            if imm_bytes == 0x6B8 and current_state_id is not None:
                st = seen_states.get(current_state_id)
                if st:
                    st.calls_register_natives = True

        # 11. Decode BR Xn (0xD61F0000 | (rn << 5))
        if (insn & 0xFFFFFC1F) == 0xD61F0000:
            rn = (insn >> 5) & 0x1F
            reg_name = f"X{rn}"

            if rn in csel_info and csel_info[rn]["targets"]:
                info = csel_info[rn]
                cond_code = info["cond"]
                cond_name = info["cond_name"]
                t_va = info["true_va"]
                f_va = info["false_va"]
                csel_va = info["csel_va"]

                patch_asm: list[str] = []
                patch_bytes = bytearray()
                if t_va is not None and f_va is not None:
                    b_cond_insn = encode_arm64_b_cond(csel_va, t_va, cond_code)
                    b_uncond_insn = encode_arm64_b(pc, f_va)
                    patch_asm = [
                        f"0x{csel_va:06x}: b.{cond_name.lower()} 0x{t_va:06x}",
                        f"0x{pc:06x}: b 0x{f_va:06x}",
                    ]
                    patch_bytes.extend(struct.pack("<II", b_cond_insn, b_uncond_insn))
                elif t_va is not None:
                    b_insn = encode_arm64_b(pc, t_va)
                    patch_asm = [f"0x{pc:06x}: b 0x{t_va:06x}"]
                    patch_bytes.extend(struct.pack("<I", b_insn))

                resolved_branches.append(
                    ResolvedIndirectBranch(
                        site_va=pc,
                        site_offset=file_off,
                        branch_reg=reg_name,
                        mnemonic=f"br x{rn}",
                        pattern_type="OLLVM CSEL Flattened Dispatcher",
                        condition=cond_name,
                        state_register=info["state_reg"],
                        compared_state_id=info["state_id"],
                        target_vas=list(info["targets"]),
                        csel_va=csel_va,
                        patch_preview_asm=patch_asm,
                        patched_bytes_hex=patch_bytes.hex(),
                    )
                )

                if info["state_id"] is not None and t_va is not None:
                    sid = info["state_id"]
                    t_off = elf.va_to_offset(t_va) or t_va
                    st_obj = OLLVMStateTransition(
                        state_id=sid,
                        block_va=t_va,
                        block_offset=t_off,
                        next_state_ids=[],
                        calls_register_natives=False,
                        description=f"Dispatched when {info['state_reg']} == 0x{sid:08x} -> 0x{t_va:06x}",
                    )
                    seen_states[sid] = st_obj
                    state_transitions.append(st_obj)

            elif rn in reg_jump_table_targets:
                jt_targets = reg_jump_table_targets[rn]
                first_target = jt_targets[0]
                b_insn = encode_arm64_b(pc, first_target)
                resolved_branches.append(
                    ResolvedIndirectBranch(
                        site_va=pc,
                        site_offset=file_off,
                        branch_reg=reg_name,
                        mnemonic=f"br x{rn}",
                        pattern_type="OLLVM Indirect Jump-Table Dispatch",
                        condition=None,
                        state_register=f"W{last_cmp_reg}" if last_cmp_reg is not None else None,
                        compared_state_id=last_cmp_val,
                        target_vas=jt_targets,
                        csel_va=None,
                        patch_preview_asm=[
                            f"0x{pc:06x}: b 0x{first_target:06x}  ; + {len(jt_targets) - 1} jump-table cases"
                        ],
                        patched_bytes_hex=struct.pack("<I", b_insn).hex(),
                    )
                )

            elif rn in reg_const and elf.is_executable_va(reg_const[rn]):
                target_va = reg_const[rn]
                b_insn = encode_arm64_b(pc, target_va)
                resolved_branches.append(
                    ResolvedIndirectBranch(
                        site_va=pc,
                        site_offset=file_off,
                        branch_reg=reg_name,
                        mnemonic=f"br x{rn}",
                        pattern_type="OLLVM Constant Computed Indirect Jump",
                        condition=None,
                        state_register=None,
                        compared_state_id=None,
                        target_vas=[target_va],
                        csel_va=None,
                        patch_preview_asm=[f"0x{pc:06x}: b 0x{target_va:06x}"],
                        patched_bytes_hex=struct.pack("<I", b_insn).hex(),
                    )
                )

            current_block_va = pc + 4

        # Stop if we hit RET and no forward branches point beyond `pc`
        if insn == 0xD65F03C0:
            max_forward_target = max(
                (t for br in resolved_branches for t in br.target_vas),
                default=0,
            )
            if pc >= max_forward_target:
                break

    return {
        "so_name": elf.name,
        "arch": elf.arch_abi,
        "fn_offset": f"0x{fn_offset:06x}",
        "fn_va": f"0x{fn_va:06x}",
        "indirect_branch_count": len(resolved_branches),
        "state_count": len(state_transitions),
        "indirect_branches": [b.to_dict() for b in resolved_branches],
        "state_transitions": [s.to_dict() for s in state_transitions],
    }


def patch_ollvm_indirect_branches(
    elf: ElfBinary,
    fn_offset: int = 0x005200,
    output_so_path: str | Path | None = None,
) -> dict[str, Any]:
    """Patches resolved `CSEL` + `BR Xn` indirect branches in-place with direct `B.<cond>` / `B` instructions."""
    analysis = resolve_ollvm_indirect_branches(elf, fn_offset=fn_offset)
    patched_image = bytearray(elf.data)
    patched_sites: list[dict[str, Any]] = []

    for br in analysis["indirect_branches"]:
        site_va = int(br["site_va"], 16)
        site_off = int(br["site_offset"], 16)
        targets = [int(t, 16) for t in br["target_vas"]]
        if not targets:
            continue

        if br["csel_va"] is not None and len(targets) >= 2:
            csel_va = int(br["csel_va"], 16)
            csel_off = elf.va_to_offset(csel_va)
            cond_str = br["condition"] or "EQ"
            cond_code = next(
                (k for k, v in ARM64_COND_NAMES.items() if v == cond_str),
                0x0,
            )
            if csel_off is not None and csel_off + 4 == site_off:
                b_cond_word = encode_arm64_b_cond(csel_va, targets[0], cond_code)
                b_uncond_word = encode_arm64_b(site_va, targets[1])
                struct.pack_into("<I", patched_image, csel_off, b_cond_word)
                struct.pack_into("<I", patched_image, site_off, b_uncond_word)
                patched_sites.append(
                    {
                        "csel_va": f"0x{csel_va:06x}",
                        "br_va": f"0x{site_va:06x}",
                        "replacement": f"b.{cond_str.lower()} 0x{targets[0]:06x}; b 0x{targets[1]:06x}",
                    }
                )
                continue

        # Fallback: replace BR Xn with direct B <targets[0]>
        b_word = encode_arm64_b(site_va, targets[0])
        struct.pack_into("<I", patched_image, site_off, b_word)
        patched_sites.append(
            {
                "br_va": f"0x{site_va:06x}",
                "replacement": f"b 0x{targets[0]:06x}",
            }
        )

    if output_so_path is not None:
        out_p = Path(output_so_path)
        out_p.parent.mkdir(parents=True, exist_ok=True)
        out_p.write_bytes(bytes(patched_image))

    return {
        "so_name": elf.name,
        "fn_offset": f"0x{fn_offset:06x}",
        "patched_branch_count": len(patched_sites),
        "patched_sites": patched_sites,
        "output_so_path": str(output_so_path) if output_so_path else None,
        "patched_elf_bytes": bytes(patched_image),
    }
