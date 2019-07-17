/*
 * dfu_helper.v
 *
 * vim: ts=4 sw=4
 *
 * Copyright (C) 2019  Sylvain Munaut <tnt@246tNt.com>
 * All rights reserved.
 *
 * BSD 3-clause, see LICENSE.bsd
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of the <organization> nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

`default_nettype none

module dfu_helper #(
	parameter integer TIMER_WIDTH = 24,
	parameter integer BTN_INVERT = 1,
	parameter integer DFU_MODE = 0		// 0 = For user app, 1 = For bootloader
)(
	// External control
	input  wire [1:0] boot_sel,
	input  wire boot_now,

	// Button
	input  wire btn_pad,

	// Outputs
	output wire btn_val,
	output reg  rst_req,

	// Clock
	input  wire clk,
	input  wire rst
);

	// Signals
	// -------

	// Button
	wire btn_iob;
	wire btn_v;
	wire btn_r;
	wire btn_f;

	// Timer
	reg [TIMER_WIDTH-1:0] timer;

	// Boot logic
	reg [1:0] wb_sel;
	reg wb_now;


	// Button logic
	// ------------

	SB_IO #(
		.PIN_TYPE(6'b000000),
		.PULLUP(1'b1),
		.IO_STANDARD("SB_LVCMOS")
	) btn_iob_I (
		.PACKAGE_PIN(btn_pad),
		.INPUT_CLK(clk),
		.D_IN_0(btn_iob)
	);

	glitch_filter #(
		.L(4),
	) btn_flt_I (
		.pin_iob_reg(btn_iob ^ BTN_INVERT),
		.cond(1'b1),
		.val(btn_v),
		.rise(btn_r),
		.fall(btn_f),
		.clk(clk),
		.rst(1'b0)	// Ensure the glitch filter has settled
					// before logic here engages
	);

	assign btn_val = btn_v;


	// Timer
	// -----

	always @(posedge clk)
		if (~btn_v)
			timer <= 0;
		else if (btn_v & ~timer[TIMER_WIDTH-1])
			timer <= timer + 1;


	// Boot Logic
	// ----------

	// Decision
	always @(posedge clk or posedge rst)
		if (rst) begin
			wb_sel  <= 2'b00;
			wb_now  <= 1'b0;
			rst_req <= 1'b0;
		end else begin
			if (boot_now) begin
				// External boot request
				wb_sel <= boot_sel;
				wb_now <= 1'b1;
				rst_req <= 1'b0;
			end else begin
				if (DFU_MODE == 1) begin
					// We're in a DFU bootloader, any button press results in
					// boot to application
					wb_sel <= 2'b10;
					wb_now <= wb_now | btn_f;
					rst_req <= 1'b0;
				end else begin
					// We're in user application, short press resets the
					// logic, long press triggers DFU reboot
					wb_sel <= 2'b01;
					wb_now  <= wb_now  | (btn_f &  timer[TIMER_WIDTH-1]);
					rst_req <= rst_req | (btn_f & ~timer[TIMER_WIDTH-1]);
				end
			end
		end

	// IP core
	SB_WARMBOOT warmboot (
		.BOOT(wb_now),
		.S0(wb_sel[0]),
		.S1(wb_sel[1])
	);

endmodule // dfu_helper
