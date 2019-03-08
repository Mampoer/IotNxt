################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../utils/json.c \
../utils/redirect.c \
../utils/signals.c \
../utils/timer.c \
../utils/utils.c 

OBJS += \
./utils/json.o \
./utils/redirect.o \
./utils/signals.o \
./utils/timer.o \
./utils/utils.o 

C_DEPS += \
./utils/json.d \
./utils/redirect.d \
./utils/signals.d \
./utils/timer.d \
./utils/utils.d 


# Each subdirectory must supply rules for building sources it contributes
utils/%.o: ../utils/%.c
	@echo 'Building file: $<'
	@echo 'Invoking: Cross GCC Compiler'
	arm-openwrt-linux-gcc -I"/home/hein/openwrt/staging_dir/target-arm_cortex-a9_glibc_eabi/usr/include/" -O3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


