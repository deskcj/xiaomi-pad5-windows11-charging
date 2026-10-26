/* Experimental r6: separate requested Type-C role from VBUS sourcing.
 * The old 0x1509 full-byte source-forcing heuristic is removed. Not a full USB-PD
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

    /* Keep the selected-slot and ABI repairs. Explicit SOURCE/SINK requests
     * remain unchanged. A DRP request must not be silently rewritten to SOURCE.
     */
    if (role != 0)
        return LegacySetRole(index, role);
    sid = *context;

    rc = PmicReadByte(sid, TYPEC_STATE_REG, &state);
    if (rc != 0)
        return rc;

    /* A request to choose a Type-C role is not a VBUS-off command.
     * Android owns VBUS through a separate regulator path. The Windows PMIC
     * already has a separate OTG callback at 0x7dd0, left byte-identical.
     * Do not tear down a USB source merely because the caller requests DRP.
     * This isolates the r5 regression; it does not supply a PD policy engine.
     */

    /* Compiler preserves index, LR and nonvolatile registers across SPMI calls.
     * In fix20 this continuation consumed clobbered w1/x9 instead.
     */
    return LegacySetRole(index, role);
}

/* Private read-only diagnostic extension of an existing no-op callback.
 * Original 0x8BE0 is MOV W0,#0; RET with no runtime-function entry.
 * Ordinary calls still return zero. Existing dispatcher 0x8DD0 validates
 * 16 input bytes and reports the returned DWORD in an existing 4-byte output.
 * No arbitrary SID/register, pointer supplied by user mode, or write is allowed.
 * This does not modify the role policy above.
 */
__declspec(noinline) u32 DiagnosticReadByte(u32 index, u32 operation,
    u32 tag_and_register, u32 version)
{
    u32 reg;
    u32 rc;
    u32 *context;
    u8 value = 0;
    if (operation != 0x51u || version != 1u
        || (tag_and_register & 0xffff0000u) != 0x4e420000u)
        return 0; /* Preserve the original no-op for all ordinary calls. */
    if (index != 1u)
        return 0x4e430061u;
    reg = tag_and_register & 0xffffu;
    if (reg != 0x110du && reg != 0x1140u && reg != 0x1153u
        && reg != 0x1307u && reg != 0x1308u && reg != 0x130bu
        && reg != 0x1310u && reg != 0x1358u && reg != 0x1370u
        && reg != 0x1506u && reg != 0x1508u && reg != 0x1509u
        && reg != 0x150bu && reg != 0x1544u)
        return 0x4e430061u;
    context = *(u32 * volatile *)(__ImageBase + PMIC_TABLE_RVA
        + (uptr)index * PMIC_SLOT_STRIDE);
    if (context == (void *)0 || context[0] != 2u || context[1] != 0x1500u)
        return 0x4e430061u;
    rc = PmicReadByte(2u, reg, &value);
    if (rc != 0)
        return 0x4e430000u | (rc & 0xffffu);
    return 0x4e420000u | (u32)value;
}
