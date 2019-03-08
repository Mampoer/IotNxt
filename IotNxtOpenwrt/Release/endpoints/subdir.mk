################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../endpoints/endpoint_check.c \
../endpoints/endpoint_iot_config.c \
../endpoints/endpoint_iot_device.c \
../endpoints/endpoint_iot_list.c 

OBJS += \
./endpoints/endpoint_check.o \
./endpoints/endpoint_iot_config.o \
./endpoints/endpoint_iot_device.o \
./endpoints/endpoint_iot_list.o 

C_DEPS += \
./endpoints/endpoint_check.d \
./endpoints/endpoint_iot_config.d \
./endpoints/endpoint_iot_device.d \
./endpoints/endpoint_iot_list.d 


# Each subdirectory must supply rules for building sources it contributes
endpoints/%.o: ../endpoints/%.c
	@echo 'Building file: $<'
	@echo 'Invoking: Cross GCC Compiler'
	arm-openwrt-linux-gcc -I"/home/hein/openwrt/staging_dir/target-arm_cortex-a9_glibc_eabi/usr/include/" -O3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


