################################################################################
# Automatically-generated file. Do not edit!
################################################################################

-include ../makefile.init

RM := rm -rf

# All of the sources participating in the build are defined here
-include sources.mk
-include utils/subdir.mk
-include src/subdir.mk
-include sockets/subdir.mk
-include file_serve/subdir.mk
-include endpoints/subdir.mk
-include subdir.mk
-include objects.mk

ifneq ($(MAKECMDGOALS),clean)
ifneq ($(strip $(C_DEPS)),)
-include $(C_DEPS)
endif
endif

-include ../makefile.defs

# Add inputs and outputs from these tool invocations to the build variables 

# All Target
all: RaptorOpenwrt

# Tool invocations
RaptorOpenwrt: $(OBJS) $(USER_OBJS)
	@echo 'Building target: $@'
	@echo 'Invoking: Cross GCC Linker'
	arm-openwrt-linux-gcc -L"/home/hein/openwrt/staging_dir/target-arm_cortex-a9_glibc_eabi/usr/lib/" -o "RaptorOpenwrt" $(OBJS) $(USER_OBJS) $(LIBS)
	@echo 'Finished building target: $@'
	@echo ' '

# Other Targets
clean:
	-$(RM) $(EXECUTABLES)$(OBJS)$(C_DEPS) RaptorOpenwrt
	-@echo ' '

.PHONY: all clean dependents

-include ../makefile.targets
