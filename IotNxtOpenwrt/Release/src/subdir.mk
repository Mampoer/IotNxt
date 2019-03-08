################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../src/IotNxtOpenwrt.c \
../src/config.c \
../src/init.c \
../src/iot_list.c \
../src/loop.c 

OBJS += \
./src/IotNxtOpenwrt.o \
./src/config.o \
./src/init.o \
./src/iot_list.o \
./src/loop.o 

C_DEPS += \
./src/IotNxtOpenwrt.d \
./src/config.d \
./src/init.d \
./src/iot_list.d \
./src/loop.d 


# Each subdirectory must supply rules for building sources it contributes
src/%.o: ../src/%.c
	@echo 'Building file: $<'
	@echo 'Invoking: Cross GCC Compiler'
	arm-openwrt-linux-gcc -I"/home/hein/openwrt/staging_dir/target-arm_cortex-a9_glibc_eabi/usr/include/" -O3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


