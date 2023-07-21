import { buildPoseidon } from "circomlibjs";
import * as ff from "./ff.js";
import * as arbo from "./arbo_utils.js";
import * as hex from "./hex.js";

const VOCDONI_SIK_SIGNATURE_LENGTH = 64

function signatureToVocdoniSikSignature(personal_sign : string) : string {
    // Discard the last byte of the personal_sign (used for recovery), different
	// that the same byte of a signature generated with go
    const buffSign = hex.toArrayBuffer(personal_sign);
    return hex.fromArrayBuffer(buffSign.slice(0, VOCDONI_SIK_SIGNATURE_LENGTH));
}  

async function calcNullifier(ffsignature : string, ffpassword : string, arboElectionId : string[]) : Promise<bigint> {        
    const poseidon = await buildPoseidon();
    const hash = poseidon([
        ffsignature,
        ffpassword,
        arboElectionId[0],
        arboElectionId[1]
    ]);
    return poseidon.F.toObject(hash);
} 

async function calcSik(address, personal_sign : string, password : string = "0") : Promise<string> {
    const arboAddress = arbo.toBigInt(address).toString();
    const safeSignature = signatureToVocdoniSikSignature(personal_sign);

    const ffsignature = ff.hexToFFBigInt(safeSignature).toString();
    const ffpassword = ff.hexToFFBigInt(password).toString();
    
    const poseidon = await buildPoseidon();
    const hash = poseidon([arboAddress, ffpassword, ffsignature]);
    return arbo.toString(poseidon.F.toObject(hash));
}

async function testSik(testAddress, testSignature : string) {
    const sik = await calcSik(testAddress, testSignature);
    console.log("sik", sik);
}

export async function GenerateCircuitInputs(
    electionId : string, 
    address : string, 
    password : string, 
    personal_sign : string, 
    voteWeight : string,
    availableWeight : string,
    sikRoot : string,
    sikSiblings : string[],
    censusRoot : string,
    censusSiblings : string[]) : Promise<any> {
    await testSik(address, personal_sign);

    const arboElectionId = await arbo.toHash(electionId);
    const signature = signatureToVocdoniSikSignature(personal_sign);

    const ffsignature = ff.hexToFFBigInt(signature).toString();
    const ffpassword = ff.hexToFFBigInt(password).toString();
    const nullifier = await calcNullifier(ffsignature, ffpassword, arboElectionId);
    return {
        // public inputs
        electionId: await arbo.toHash(electionId),
        nullifier: nullifier.toString(),
        availableWeight,
        voteHash: await arbo.toHash(hex.fromBigInt(BigInt(availableWeight))),
        sikRoot,
        censusRoot,
        // private inputs
        address: arbo.toBigInt(address).toString(),
        password: ffpassword,
        signature: ffsignature,
        voteWeight,
        sikSiblings,
        censusSiblings,
    }
}