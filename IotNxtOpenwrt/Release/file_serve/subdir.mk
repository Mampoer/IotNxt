################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../file_serve/file_serve.c \
../file_serve/http_parser.c \
../file_serve/picohttpparser.c 

OBJS += \
./file_serve/file_serve.o \
./file_serve/http_parser.o \
./file_serve/picohttpparser.o 

C_DEPS += \
./file_serve/file_serve.d \
./file_serve/http_parser.d \
./file_serve/picohttpparser.d 


# Each subdirectory must supply rules for building sources it contributes
file_serve/%.o: ../file_serve/%.c
	@echo 'Building file: $<'
	@echo 'Invoking: Cross GCC Compiler'
	arm-openwrt-linux-gcc -I"/home/hein/openwrt/staging_dir/target-arm_cortex-a9_glibc_eabi/usr/include/" -O3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


