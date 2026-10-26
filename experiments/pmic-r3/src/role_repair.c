/* Experimental r3 repair of fix20's calling convention and selected-slot guard.
 * This retains the author's unvalidated 0x1509 role heuristic. Not a full USB-PD
 * policy implementation, not a claim of Android-equivalent charging.
 * External calls are direct branches resolved by the constrained COFF patcher.
 */
typedef unsigned int u32;
typedef unsigned char u8;
typedef unsigned __int64 uptr;

extern u8 __ImageBase[];
extern u32 PmicReadByte(u32 sid, u32 reg, u8 *value);
extern u32 PmicMaskedWrite(u32 sid, u32 reg, u32 mask, u32 value);
extern u32 LegacySetRole(u32 index, u32 role);

#define INVALID_OR_NOT_READY 0x61u
#define PMIC_TABLE_RVA 0xD548u
#define PMIC_SLOT_STRIDE 0x30u
#define NABU_SUPPORTED_LOGICAL_SLOTS 2u
#define TYPEC_STATE_REG 0x1509u
#define OTG_COMMAND_REG 0x1140u

__declspec(noinline) u32 RepairSetRole(u32 index, u32 role)
{
    u32 rc;
    u32 sid;
    u8 state = 0;
    u32 *context;

    /* The audited nabu backend uses logical slot 1. Slot 0 is the other
     * legacy slot; reject unknown indices before touching this private table.
     * This profile is specific to the audited nabu binary, not other tablets.
     */
    if (index >= NABU_SUPPORTED_LOGICAL_SLOTS)
        return INVALID_OR_NOT_READY;
    context = *(u32 * volatile *)(__ImageBase + PMIC_TABLE_RVA
        + (uptr)index * PMIC_SLOT_STRIDE);
    if (context == (void *)0)
        return INVALID_OR_NOT_READY;

    /* Original fix20 at 0x2654 uses CBZ x1: its special path is selected by
     * role == 0, without an index == 0 restriction. The nabu backend calls
     * logical slot 1 (SID 2). r1/r2 incorrectly bypassed the repair there.
     * Preserve the caller index and use the SELECTED valid context.
     * The inherited full-byte heuristic remains experimental.
     */
    if (role != 0)
        return LegacySetRole(index, role);
    sid = *context;

    rc = PmicReadByte(sid, TYPEC_STATE_REG, &state);
    if (rc != 0)
        return rc;

    /* Compatibility policy from fix20, deliberately not reinterpreted as a
     * proven CC/PD contract. Full policy validation needs physical testing.
     */
    if ((u32)state >= 5u && (u32)state <= 34u)
        return LegacySetRole(index, 4u);

    rc = PmicMaskedWrite(sid, OTG_COMMAND_REG, 1u, 0u);
    if (rc != 0)
        return rc;

    /* Compiler preserves index, LR and nonvolatile registers across SPMI calls.
     * In fix20 this continuation consumed clobbered w1/x9 instead.
     */
    return LegacySetRole(index, role);
}
