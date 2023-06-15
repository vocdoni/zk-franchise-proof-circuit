import { buildPoseidon } from "circomlibjs";
import * as ff from "./ff.js";
import * as arbo from "./arbo_utils.js";
import * as hex from "./hex.js";

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

export async function GenerateCircuitInputs(
    electionId : string, 
    address : string, 
    password : string, 
    signature : string, 
    voteWeight : string,
    availableWeight : string,
    cikRoot : string,
    cikSiblings : string[],
    censusRoot : string,
    censusSiblings : string[]) : Promise<any> {
    
    const arboElectionId = await arbo.toHash(electionId);

    const ffsignature = ff.hexToFFBigInt(signature).toString();
    const ffpassword = ff.hexToFFBigInt(password).toString();

    const nullifier = await calcNullifier(ffsignature, ffpassword, arboElectionId);
    return {
        // public inputs
        electionId: await arbo.toHash(electionId),
        nullifier: nullifier.toString(),
        availableWeight,
        voteHash: await arbo.toHash(hex.fromBigInt(BigInt(availableWeight))),
        cikRoot,
        censusRoot,
        
        // private inputs
        address: arbo.toBigInt(address).toString(),
        password: ffpassword,
        signature: ffsignature,
        
        voteWeight,
        cikSiblings,
        censusSiblings,
    }
}