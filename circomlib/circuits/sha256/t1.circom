/*
    Copyright 2018 0KIMS association.

    This file is part of circom (Zero Knowledge Circuit Compiler).

    circom is a free software: you can redistribute it and/or modify it
    under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    circom is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
    or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public
    License for more details.

    You should have received a copy of the GNU General Public License
    along with circom. If not, see <https://www.gnu.org/licenses/>.
*/

include "../binsum.circom";
include "sigma.circom";
include "ch.circom";

template T1() {
    signal input h[32];
    signal input e[32];
    signal input f[32];
    signal input g[32];
    signal input k[32];
    signal input w[32];
    signal output out[32];

    component sum = BinSum(32, 5);
    component ch = Ch(32);

    component bigsigma1 = BigSigma(6, 11, 25);

    for (var ki=0; ki<32; ki+=1) {
        bigsigma1.in[ki] <== e[ki];
        ch.a[ki] <== e[ki];
        ch.b[ki] <== f[ki];
        ch.c[ki] <== g[ki];
    }
    for (var ki=0; ki<32; ki+=1) {
        sum.in[0][ki] <== h[ki];
        sum.in[1][ki] <== bigsigma1.out[ki];
        sum.in[2][ki] <== ch.out[ki];
        sum.in[3][ki] <== k[ki];
        sum.in[4][ki] <== w[ki];
    }
    for (var ki=0; ki<32; ki+=1) {
        out[ki] <== sum.out[ki];
    }
}
