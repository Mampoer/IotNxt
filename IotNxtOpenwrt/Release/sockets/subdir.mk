################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../sockets/http.c \
../sockets/io.c \
../sockets/resolv.c \
../sockets/ssl.c 

OBJS += \
./sockets/http.o \
./sockets/io.o \
./sockets/resolv.o \
./sockets/ssl.o 

C_DEPS += \
./sockets/http.d \
./sockets/io.d \
./sockets/resolv.d \
./sockets/ssl.d 


# Each subdirectory must supply rules for building sources it contributes
sockets/%.o: ../sockets/%.c
	@echo 'Building file: $<'
	@echo 'Invoking: Cross GCC Compiler'
	arm-openwrt-linux-gcc -I"/home/hein/openwrt/staging_dir/target-arm_cortex-a9_glibc_eabi/usr/include/" -O3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


