#ifndef _QLCNIC_COMPAT_H
#define _QLCNIC_COMPAT_H

#ifdef CONFIG_DCB
#define CONFIG_QLCNIC_DCB
#endif

#ifdef CONFIG_HWMON
#define CONFIG_QLCNIC_HWMON
#endif

#endif
