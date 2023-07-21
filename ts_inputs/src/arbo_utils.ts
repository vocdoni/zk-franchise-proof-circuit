import { toArrayBuffer, fromArrayBuffer, fromBigInt } from "./hex.js";
import { sha256 } from '@ethersproject/sha2';
import { Buffer } from 'buffer';


function strip0x(value: string): string {
    return value.startsWith('0x') ? value.substring(2) : value;
}

export function toBigInt(str: string): bigint {
    const strBuff = toArrayBuffer(str);
    const hexArbo = fromArrayBuffer(strBuff.reverse());
    return BigInt("0x" + hexArbo);
}

export function toString(n: bigint): string {
    const nStr = fromBigInt(n);
    const nBuff = toArrayBuffer(nStr);
    return fromArrayBuffer(nBuff.reverse());
}

export async function toHash(input: string): Promise<string[]> {
    const inputBuff = toArrayBuffer(input);
    const inputHash = sha256(inputBuff);
    const inputHashBuff = new Uint8Array(Buffer.from(strip0x(inputHash), 'hex'));

    const splitArboInput = [
        fromArrayBuffer(inputHashBuff.subarray(0, 16).reverse()),
        fromArrayBuffer(inputHashBuff.subarray(16, 32).reverse()),
    ];

    return [BigInt('0x' + splitArboInput[0]).toString(), BigInt('0x' + splitArboInput[1]).toString()];
}