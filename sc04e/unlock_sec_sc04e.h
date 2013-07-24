#define DEFINE_CHECK(name)  { name##_address, VERNAME(check_##name) }

static const unsigned long int VERNAME(check_reset_security_ops)[] = {
  0xe59f2008,                                                                     //      LDR     R2, =default_security_ops [PC + 0x10]
  0xe59f3008,                                                                     //      LDR     R3, =security_ops [PC + 0x10]
  0xe5832000,                                                                     //      STR     R2, [R3]
  0xe12fff1e,                                                                     //      BX      LR
  default_security_ops_address,
  security_ops_address,
  0
};

static const unsigned long int VERNAME(check_sec_restrict_uid)[] = {
  0xe92d40f7,                                                                     //      STMPW   [SP], { R0-R2, R4-R7, LR }
  0xe59f012c,                                                                     //      LDR     R0, =tasklist_lock [PC + $134]
  0xeb000000 + BL_REL(sec_restrict_uid_address + 8, _raw_read_lock_address),      //      BL      _raw_read_lock
  0
};

static const unsigned long int VERNAME(check_sec_check_execpath)[] = {
  0xe2503000,                                                                     //      SUBS    R3, R0, #$0
  0xe92d41f0,                                                                     //      STMPW   [SP], { R4-R8, LR }
  0xe1a06001,                                                                     //      MOV     R6, R1
  0x01a06003,                                                                     //      MOVEQ   R6, R3
  0x0a000031,                                                                     //      BEQ     PC + $cc
  0xeb000000 + BL_REL(sec_check_execpath_address + 20, get_mm_exe_file_address),  //      BL      get_mm_exe_file
  0
};

static const unsigned long int VERNAME(check_sys_execve)[] = {
  0xe92d4ff0,                                                                     //      STMPW   [SP], { R4-R11, LR }
  0xe24dd014,                                                                     //      SUB     SP, SP, #$14
  0xe1a05003,                                                                     //      MOV     R5, R3
  0xe1a06002,                                                                     //      MOV     R6, R2
  0xe58d100c,                                                                     //      STR     R1, [SP, #$c]
  0xeb000000 + BL_REL(sys_execve_address + 20, getname_address),                  //      BL      getname
  0xe3700a01,                                                                     //      CMNS    R0, #$1000
  0xe1a04000,                                                                     //      MOV     R4, R0
  0x81a05000,                                                                     //      MOVHI   R5, R0
  0x8a00009e,                                                                     //      BHI     PC + $a6                   ; IS_ERR(filename)
  0xe1a0200d,                                                                     //      MOV     R2, SP
  0xe3c23d7f,                                                                     //      BIC     R3, R2, #$1fc0
  0xe3c3303f,                                                                     //      BIC     R3, R3, #$3f
  0xe593300c,                                                                     //      LDR     R3, [R3, #$c]
  0xe5933204,                                                                     //      LDR     R3, [R3, #$204]
  0xe5932004,                                                                     //      LDR     R2, [R3, #$4]
  0xe3520000,                                                                     //      CMPS    R2, #$0
  0x0a00000e,                                                                     //      BEQ     PC + $40
  0xe5932008,                                                                     //      LDR     R2, [R3, #$8]
  0xe3520000,                                                                     //      CMPS    R2, #$0
  0x0a00000b,                                                                     //      BEQ     PC + $34
  0
};

static const unsigned long int VERNAME(patched_sys_execve)[] = {
  0xe92d4ff0,                                                                     //      STMPW   [SP], { R4-R11, LR }
  0xe24dd014,                                                                     //      SUB     SP, SP, #$14
  0xe1a05003,                                                                     //      MOV     R5, R3
  0xe1a06002,                                                                     //      MOV     R6, R2
  0xe58d100c,                                                                     //      STR     R1, [SP, #$c]
  0xeb000000 + BL_REL(sys_execve_address + 20, getname_address),                  //      BL      getname
  0xe3700a01,                                                                     //      CMNS    R0, #$1000
  0xe1a04000,                                                                     //      MOV     R4, R0
  0x81a05000,                                                                     //      MOVHI   R5, R0
  0x8a00009e,                                                                     //      BHI     PC + $a6
  0xe1a03005,                                                                     //      MOV     R3, R5
  0xe1a00004,                                                                     //      MOV     R0, R4
  0xe59d100c,                                                                     //      LDR     R1, [SP, #$c]
  0xe1a02006,                                                                     //      MOV     R2, R6
  0xeb000000 + BL_REL(sys_execve_address + 56, do_execve_address),                //      BL      do_execve
  0xe1a05000,                                                                     //      MOV     R5, R0
  0xe1a00004,                                                                     //      MOV     R0, R4
  0xeb000000 + BL_REL(sys_execve_address + 68, putname_address),                  //      BL      putname
  0xe1a00005,                                                                     //      MOV     R0, R5
  0xe28dd014,                                                                     //      ADD     SP, SP, #$14
  0xe8bd8ff0,                                                                     //      LDMUW   [SP], { R4-R11, PC }
  0
};

static struct check_code_t VERNAME(check_code)[] =
{
  DEFINE_CHECK(reset_security_ops),
  DEFINE_CHECK(sec_restrict_uid),
  DEFINE_CHECK(sec_check_execpath),
  DEFINE_CHECK(sys_execve),
  { 0 }
};

static const struct patch_info_t VERNAME(patch_info) = {
  .sec_restrict_uid = sec_restrict_uid_address,
  .sec_check_execpath = sec_check_execpath_address,
  .sys_execve = sys_execve_address,
  .security_ops = security_ops_address,
  .default_security_ops = default_security_ops_address,
  .patched_sys_execve = VERNAME(patched_sys_execve),
};

#undef VERNAME
#undef DEFINE_CHECK
#undef reset_security_ops_address
#undef default_security_ops_address
#undef security_ops_address
#undef sec_restrict_uid_address
#undef sec_check_execpath_address
#undef sys_execve_address
#undef _raw_read_lock_address
#undef get_mm_exe_file_address
#undef getname_address
#undef do_execve_address
#undef putname_address

/*
vi:ts=2:nowrap:ai:expandtab:sw=2
*/
