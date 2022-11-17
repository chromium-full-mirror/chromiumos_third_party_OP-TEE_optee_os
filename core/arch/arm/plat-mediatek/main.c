// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2015, Linaro Limited
 */

#include <console.h>
#include <drivers/gic.h>
#include <drivers/serial8250_uart.h>
#include <kernel/boot.h>
#include <kernel/panic.h>
#include <mm/core_memprot.h>
#include <platform_config.h>
#include <stdint.h>

#if defined(CFG_UART_ENABLE)
register_phys_mem_pgdir(MEM_AREA_IO_NSEC,
			CONSOLE_UART_BASE, SERIAL8250_UART_REG_SIZE);
#endif

static struct serial8250_uart_data console_data;

register_ddr(CFG_DRAM_BASE, BIT64(CFG_CORE_ARM64_PA_BITS) - CFG_DRAM_BASE);

#ifdef CFG_GIC
static struct gic_data gic_data;

register_phys_mem_pgdir(MEM_AREA_IO_SEC, GIC_BASE + GICD_OFFSET,
			CORE_MMU_PGDIR_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_SEC, GIC_BASE + GICC_OFFSET,
			CORE_MMU_PGDIR_SIZE);

void main_init_gic(void)
{
	gic_init_base_addr(&gic_data, GIC_BASE + GICC_OFFSET,
			   GIC_BASE + GICD_OFFSET);

	itr_init(&gic_data.chip);
}

void itr_core_handler(void)
{
	gic_it_handle(&gic_data);
}
#endif

void console_init(void)
{
#if defined(CFG_UART_ENABLE)
	serial8250_uart_init(&console_data, CONSOLE_UART_BASE,
			     CONSOLE_UART_CLK_IN_HZ, CONSOLE_BAUDRATE);
	register_serial_console(&console_data.chip);
#endif
}
