const path = require("path");
const tester = require("circom").tester;
const chai = require("chai");
const assert = chai.assert;

export {};

describe("Census test", function () {
    this.timeout(200000);

    it("Test Census 3lvl 1+0 claims, correct voter proof & incorrect revealKeys", async () => {
        const circuit = await tester(
            path.join(__dirname, "circuits", "census4lvl.circom"),
            {reduceConstraints: false}
        );
    
        // using correct voter proof, but incorrect revealKeys
        const witness = await circuit.calculateWitness({
            censusRoot: "93074199606177410108982832008118517629723592135537362309254185060566702990886",
            censusSiblings: ["0","0","0","0"],
            privateKey: "6190793965647866647574058687473278714480561351424348391693421151024369116465",
            voteSigS: "2209631892358909859397227882534860536786213289219644305743688183951383321555",
            voteSigR8x: "8553678144208642175027223770335048072652078621216414881653012537434846327449",
            voteSigR8y: "5507837342589329113352496188906367161790372084365285966741761856353367255709",
            voteValue: "1",
            electionId: "10",
            nullifier: "5482502190698122543507050012922267324433666089315343653961928581094977573855",
            relayerPublicKey: "100",
            relayerProof: "5310453724638211502974974048672254152837836404760801353912687712949736620975",
            revealKey: ["0"],
            commitKey: ["951383894958571821976060584138905353883650994872035011055912076785884444545"]
        });
        await circuit.checkConstraints(witness);
    });

    it("Test Census 3lvl 1+0 claims, fake-voter proof & correct revealKeys", async () => {
        const circuit = await tester(
            path.join(__dirname, "circuits", "census4lvl.circom")
        );
    
        // using incorrect voter proof, but correct revealKeys
        const witness = await circuit.calculateWitness({
            censusRoot: "0",
            censusSiblings: ["0","0","0","0"],
            privateKey: "0",
            voteSigS: "0",
            voteSigR8x: "0",
            voteSigR8y: "0",
            voteValue: "1",
            electionId: "10",
            nullifier: "0",
            relayerPublicKey: "100",
            relayerProof: "5310453724638211502974974048672254152837836404760801353912687712949736620975",
            revealKey: ["0"],
            commitKey: ["951383894958571821976060584138905353883650994872035011055912076785884444545"]
        });
        await circuit.checkConstraints(witness);
    });
    
    it("Test Census 9lvl 1+10 claims, correct voter proof & incorrect revealKeys", async () => {
        const circuit = await tester(
            path.join(__dirname, "circuits", "census10lvl.circom")
        );
    
        // using correct voter proof, but incorrect revealKeys
        const witness = await circuit.calculateWitness({
            censusRoot: "16414506614527731245082282695072997100882829711721740860077398183201218169628",
            censusSiblings: ["84125060033484286117466904797950987149291166641933755598034430284434981502255","75850967783849669988450069617104137991512608275570305959225494269142294140942","15460148989205751279781666788871529320173146664653448229271903139343963359260","0","45868242572431872430298447144201259009981968477116420036766265178022491385111","0","0","0","0","0"],
            privateKey: "6190793965647866647574058687473278714480561351424348391693421151024369116465",
            voteSigS: "2209631892358909859397227882534860536786213289219644305743688183951383321555",
            voteSigR8x: "8553678144208642175027223770335048072652078621216414881653012537434846327449",
            voteSigR8y: "5507837342589329113352496188906367161790372084365285966741761856353367255709",
            voteValue: "1",
            electionId: "10",
            nullifier: "5482502190698122543507050012922267324433666089315343653961928581094977573855",
            relayerPublicKey: "100",
            relayerProof: "5310453724638211502974974048672254152837836404760801353912687712949736620975",
            revealKey: ["0","1","2","3","4","5","6","7","8","9"],
            commitKey: ["951383894958571821976060584138905353883650994872035011055912076785884444545","2279272124503809695177170942549831206840003426178943720957919922723804431629","13132721937331725951616278520078927153934890115891049388516726302689567578587","18442948218473893283924843755589817822427508265938532728709302914879634892749","12084275295331946986340693313402797442518501813308109048188923105310253309791","8848178909881593552457486887414951287175932326882038406284807189221803056772","11899825037888572919115683806964441129093688456736926044161948748098370273777","18223672980974199262634410925076688222177561421223540262380286416350262836118","14902265407969970344510537202111282642386325062447119312980315937375856457675","6208962682047338057668738897828144680773401396295832555062038707095136280140"]
        });
        await circuit.checkConstraints(witness);
    });
    
    it("Test Census 19lvl 1+100 claims, correct voter proof & incorrect revealKeys", async () => {
        const circuit = await tester(
            path.join(__dirname, "circuits", "census20lvl.circom")
        );
    
        // using correct voter proof, but incorrect revealKeys
        const witness = await circuit.calculateWitness({
            censusRoot: "52714749769649365475241049292053378257658200980780669305644105529834295736",
            censusSiblings: ["106813645162546289224049357396564267288714707259955710736491566699124436031271","63404236871424836941562487147339451205946923477357749898733196309348167526176","87275281606057765190948023730764111139443814792027144266232950209154997343778","69817517366437120721160242158700076983679076131340441760721677224057184988186","48227129245045152057302850896138033855034560275958873860996868266816493241866","58193760287389497811643633066059786518146416701630441254963119876115539766030","71678845388617557598442232705382095262832290347911911941587127359827771635498","18520140670102611109777318779072207640789613286936303603217434166582962667804","109796154387931238679714321043113963953645589025008009303710270228381089049647","94715622254143165862487420903596452130922119669721320427445782173463644687122","40126464002023312845626744847047204838017318588163760505226991131988093774858","0","0","0","0","0","0","0","0","0"],
            privateKey: "6190793965647866647574058687473278714480561351424348391693421151024369116465",
            voteSigS: "2209631892358909859397227882534860536786213289219644305743688183951383321555",
            voteSigR8x: "8553678144208642175027223770335048072652078621216414881653012537434846327449",
            voteSigR8y: "5507837342589329113352496188906367161790372084365285966741761856353367255709",
            voteValue: "1",
            electionId: "10",
            nullifier: "5482502190698122543507050012922267324433666089315343653961928581094977573855",
            relayerPublicKey: "100",
            relayerProof: "5310453724638211502974974048672254152837836404760801353912687712949736620975",
            revealKey: ["0","1","2","3","4","5","6","7","8","9","10","11","12","13","14","15","16","17","18","19","20","21","22","23","24","25","26","27","28","29","30","31","32","33","34","35","36","37","38","39","40","41","42","43","44","45","46","47","48","49"],
            commitKey: ["951383894958571821976060584138905353883650994872035011055912076785884444545","2279272124503809695177170942549831206840003426178943720957919922723804431629","13132721937331725951616278520078927153934890115891049388516726302689567578587","18442948218473893283924843755589817822427508265938532728709302914879634892749","12084275295331946986340693313402797442518501813308109048188923105310253309791","8848178909881593552457486887414951287175932326882038406284807189221803056772","11899825037888572919115683806964441129093688456736926044161948748098370273777","18223672980974199262634410925076688222177561421223540262380286416350262836118","14902265407969970344510537202111282642386325062447119312980315937375856457675","6208962682047338057668738897828144680773401396295832555062038707095136280140","605134270423674385597970752853025127571841647033541397542004991659966706055","13102694700057465179944624100082420582123500524537826601559534106916901257520","21052695629190546394989607794799171059124754590739990603259466855014838424110","2718909611621376226865828200594649060166921047311302744396589689885641330093","18024406157736560703308537833740726814155606126448191059043629547773863688057","4175447108483937532113339984256404766238908112486062113397113561377255476611","6483277781737385442409653042772493987205395046145624489266799449189818588577","6294475023919549704404111525594135399827671102987390391183768565580884407846","14016258209192415532724567748023748859285644828000956895430551070135535092643","14386313485780366932463481999309991330526254664397696402290128521971408904827","1297939952686470096118527486627517121932549802288213666194612289253788489325","4532329012139259650852585007906557580715907815959305758893724831309213032835","354538458376787894335404819910715971733438150176107364134634392851690144932","556068696143231644287072961047024192435078393231421232088758377513754774538","3741034370497499130789344443966343667859418669414430662920887277002191012403","4044672803846305646330271986192467418472167479078400505401160090083686898154","20193856670521460664731919701711727014843649356979661959584501347393496113472","12160745118096884987257537481459914653165469908344815240818380041746017812563","11596134642427769257973824598290590623927450986173593333890558456755917487580","5975977376838912302629866234854139205442380000945616234641073979255663880346","11499097465829018590118166345026821024855979358392744579722384656086941444863","4792236032125419395019564699428274682431854642871516239100981274300521803989","10131119200544388457558313388415462345307461389590513332836676346889763803441","14720274817385788387666092026234541896034359881550599364715517932602691172417","6891845676301994330074879811336909946798139330693335211214383517277346957380","21275117040579759119528842382437115995203362860960965060922017782103076789191","672814321706603168234875559827725447245701235760942006787523522981205774875","12359838665925559025767331344602697114298764449743378917561703456408720828820","11238408802997420866221934316113909645223929012688404255052551657454404104208","19098644836992087053794061812837245656118632767408874128478181633329407416974","15432835534741356787612998353026805293976981531248885338187634700734818634087","3457473656445341974568961643635182176853642530168880259388514242909088529504","15790407067424637032066791620272072203644651689859053771222027790253670657057","20486665356748052828494776517315500148093069529198903111422733420963770269385","14433223225306281482531539358066479668871127269548213796307233389824855130587","18640972925746416595494712008015162242979097206984377155311314648249449106647","13886979786424588973506479790310834092378157141524249982655141260005053691124","11595381457796934893108929410862878015464876162611153140026165943832656342158","4139697278680470753196565848471462440275714125396621820433992608977093887873","15202397391057921875009979971208907050600266914771872254349291138501538333013"]
        });
        await circuit.checkConstraints(witness);
    });
});
