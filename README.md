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

* Unlock MIYABI LSM for SH-02E/SH-04E.

	`unlock_lsm_sh02e`
	`unlock_lsm_sh04e`

* Unlock MMC protected partitions for for SH-02E/SH-04E.

	`unlock_mmc_sh02e`
	`unlock_mmc_sh04e`

* Unlock SEC LSM for SC-04E.

	`unlock_sec_sc04e`
	
* Disable TOMOYO LSM for Panasonic and LG devices.

	`disable_ccsecurity`
	
* Call reset_security_ops to disable normal LSM.

	`reset_security_ops`

* Print kernel symbols out.

	`kallsymsprint`
	
