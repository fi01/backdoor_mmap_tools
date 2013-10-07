backdoor_mmap_tools
======================

This code is still ugly, please re-write it and send pull-requests, if you want to use this.


How to use
========

* Install mmap backdoor

  `install_backdoor`

* Uninstall mmap backdoor

	`install_backdoor -u`

* Run shell with temporary root privilege.

	`run_root_shell`

* Run command "/data/local/autoexec.sh" with root privilege.

	`run_autoexec`

* Unlock fjsec LSM for Fujitsu devices.

	`unlock_lsm_fjsec`

* Unlock MIYABI LSM for SHARP devices.
Support devices are: SBM203SH/SH-09D/SH-02E/SH-04E/SH-05E/SH-06E/SHL21

	`unlock_lsm_sbm203sh`
	`unlock_lsm_sh09d`
	`unlock_lsm_sh02e`
	`unlock_lsm_sh04e`
	`unlock_lsm_sh05e`
	`unlock_lsm_sh06e`
	`unlock_lsm_shl21`

* Unlock MMC protected partitions for SHARP devices.
Support devices are: SBM203SH/SH-09D/SH-02E/SH-04E/SH-05E/SH-06E/SHL21

	`unlock_mmc_sbm203sh`
	`unlock_mmc_sh09d`
	`unlock_mmc_sh02e`
	`unlock_mmc_sh04e`
	`unlock_mmc_sh05e`
	`unlock_mmc_sh06e`
	`unlock_mmc_shl21`

* Unlock SEC LSM for SC-04E.

	`unlock_sec_sc04e`
	
* Disable TOMOYO LSM for Panasonic and LG devices.

	`disable_ccsecurity`
	
* Call reset_security_ops to disable normal LSM.

	`reset_security_ops`

* Print kernel symbols out.

	`kallsymsprint`

