import r1cs      from './r1cs.txt';
import witness   from './witness.txt';
import key       from './setup.txt';

var startTime, endTime;

function start() {
  startTime = new Date();
  console.log("starting...")
};

function end() {
  endTime = new Date();
  var timeDiff = endTime - startTime; //in ms
  // strip the ms
  timeDiff /= 1000;

  // get seconds 
  var seconds = Math.round(timeDiff);
  console.log(seconds + " seconds");
}

async function go() {
    alert("loading plonkit");
    let plonkit = await import('./pkg/plonkit.js');
    console.log("begin ", new Date());
    let proof=plonkit.prove(r1cs,witness,key);
    console.log(proof);
    console.log("end", new Date());
} 

go()

