; PM8150B/nabu parameter encoding only. Internal ABI: W8 input in mA/mV,
; W8 output register code; W9 and NZCV scratch. All other registers and SP
; remain untouched. No memory access, calls, allocation, timer or I/O here.
; Caps are upper bounds, never a replacement for a lower caller limit.
; Hardware steps: FCC/USB 50mA; DC 40mA; FV (mV - 3600)/10.
; Board ceilings: FCC 5900mA, FV 4470mV, USB 3000mA.
; These are true leaf helpers: no .pdata required (Microsoft Arm64 EH).

        AREA |.text|, CODE, READONLY, ALIGN=2
        EXPORT EncodeFCC
        EXPORT EncodeFCCEnd
        EXPORT EncodeFV
        EXPORT EncodeFVEnd
        EXPORT EncodeUSB
        EXPORT EncodeUSBEnd
        EXPORT EncodeDC
        EXPORT EncodeDCEnd

EncodeFCC
        mov     w9, #5900
        cmp     w8, w9
        csel    w8, w8, w9, ls
        mov     w9, #50
        udiv    w8, w8, w9
        ret
EncodeFCCEnd

EncodeFV
        mov     w9, #4470
        cmp     w8, w9
        csel    w8, w8, w9, ls
        mov     w9, #3600
        cmp     w8, w9
        csel    w8, w8, w9, hs
        sub     w8, w8, w9
        mov     w9, #10
        udiv    w8, w8, w9
        ret
EncodeFVEnd

EncodeUSB
        mov     w9, #3000
        cmp     w8, w9
        csel    w8, w8, w9, ls
        mov     w9, #50
        udiv    w8, w8, w9
        ret
EncodeUSBEnd

EncodeDC
        mov     w9, #1200
        cmp     w8, w9
        csel    w8, w8, w9, ls
        mov     w9, #40
        udiv    w8, w8, w9
        ret
EncodeDCEnd
        END
