enum {
  DEV_NOT_SUPPORTED = 0,
  DEV_F11D_V24R40A,
  DEV_IS17SH_01_00_04,
  DEV_ISW12K_010_0_3000,
  DEV_SCL21_KDALJD,
  DEV_ISW13F_V69R51I,
  DEV_SONYTABS_RELEASE5A,
  DEV_SONYTABP_RELEASE5A,
  DEV_SH04E_01_00_02,
  DEV_SOL21_9_1_D_0_395,
  DEV_HTL21_JRO03C,
};

extern int detect_device(void);
extern int print_reason_device_not_supported(void);

