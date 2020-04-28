/*
 * ice40_serdes_dff.v
 *
 * vim: ts=4 sw=4
 *
 * Copyright (C) 2020  Sylvain Munaut <tnt@246tNt.com>
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

module ice40_serdes_dff #(
	parameter integer NEG = 0,
	parameter integer ENA = 0,
	parameter integer RST = 0,
	parameter integer SERDES_GRP = -1,
	parameter BEL = ""
)(
	input  wire d,
	output wire q,
	input  wire e,
	input  wire r,
	input  wire c
);
	parameter TYPE = (RST ? 4 : 0) | (ENA ? 2 : 0) | (NEG ? 1 : 0);

	generate
		if (TYPE == 0)			// Simple
			(* BEL=BEL, SERDES_GRP=SERDES_GRP *)
			(* dont_touch *)
			SB_DFF dff_I (
				.D(d),
				.Q(q),
				.C(c)
			);

		else if (TYPE == 1)		// NEG
			(* BEL=BEL, SERDES_GRP=SERDES_GRP *)
			(* dont_touch *)
			SB_DFFN dff_I (
				.D(d),
				.Q(q),
				.C(c)
			);

		else if (TYPE == 2)		//     ENA
			(* BEL=BEL, SERDES_GRP=SERDES_GRP *)
			(* dont_touch *)
			SB_DFFE dff_I (
				.D(d),
				.Q(q),
				.E(e),
				.C(c)
			);

		else if (TYPE == 3)		// NEG ENA
			(* BEL=BEL, SERDES_GRP=SERDES_GRP *)
			(* dont_touch *)
			SB_DFFNE dff_I (
				.D(d),
				.Q(q),
				.E(e),
				.C(c)
			);

		else if (TYPE == 4)		//         RST
			(* BEL=BEL, SERDES_GRP=SERDES_GRP *)
			(* dont_touch *)
			SB_DFFR dff_I (
				.D(d),
				.Q(q),
				.R(r),
				.C(c)
			);

		else if (TYPE == 5)		// NEG     RST
			(* BEL=BEL, SERDES_GRP=SERDES_GRP *)
			(* dont_touch *)
			SB_DFFNR dff_I (
				.D(d),
				.Q(q),
				.R(r),
				.C(c)
			);

		else if (TYPE == 6)		//     ENA RST
			(* BEL=BEL, SERDES_GRP=SERDES_GRP *)
			(* dont_touch *)
			SB_DFFER dff_I (
				.D(d),
				.Q(q),
				.E(e),
				.R(r),
				.C(c)
			);

		else if (TYPE == 7)		// NEG ENA RST
			(* BEL=BEL, SERDES_GRP=SERDES_GRP *)
			(* dont_touch *)
			SB_DFFNER dff_I (
				.D(d),
				.Q(q),
				.E(e),
				.R(r),
				.C(c)
			);

	endgenerate

endmodule
