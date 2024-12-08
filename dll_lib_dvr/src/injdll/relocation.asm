

.CODE
ReLocation PROC
    push rax          ; 保存 rax 寄存器的值
    call get_return_address
    get_return_address:
    pop rax       ; 获取返回地址，这个地址实际上是调用点的 RIP 地址
    ret
ReLocation ENDP
 
END
