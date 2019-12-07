package cz.vernjan.ctf.hv19.day06

// Removed all non-alphabet characters (except *)
const val cipherText = "*F*ra*n*cisBaco*n**w*a*s**a*nE*ng*lishph*i*l*os*o*p*hera*n*d*s*tat*e*sm*a*nw*h*ose*rve*d*a" +
        "*sAt*t*or*n*eyGen*e*ralandas*L*or*d**Ch*an*ce*l*l*orof*En*g*l*an*d*Hi*s**w*orksar*e*c*red*it*e*dw*ith*d*e" +
        "*ve*lo*pi*ng**t*h*e*sci*e*nt*i*ficme*t*hodandre*m*ai*ned*in*fl*u*en*ti*al*th*rou*gh*t*hes*cien*tific*r*ev" +
        "*o*l*u*ti*o*n*B*a*co*nh*as**b*e*e*nca*l*led*th*e*f*ath*e*ro*f*emp*iric*i*s*m*Hi*s*wor*ksar*g*uedforth*e*p" +
        "o*ssi*bi*li*t*y*ofs*c*ie*n*tifi*c**kno*wl*edg*eb*a*se*d*onl*y*u*p*oni*n*du*c*t*i*ve*r*ea*s*onin*g**a*ndc*" +
        "aref*u*l*o*bs*er*v*ationo*f**e*v*e*nt*s*in*na*tur*e*Mo*st**i*mp*ort*an*t*l*y**he*a*rgue*dsc*i*en*c*eco*ul" +
        "d**b*e*a*c*hi*evedbyus*e*ofa*s*ce*p*t*ical*a*nd*me*t*hod*i*ca*l**a*pp*roa*chwh*er*eby*s*cientist*s*ai*m*t" +
        "*o*avo*i*dm*i*sl*ead*in*g*themsel*ve*s*A*lth*oug*h*h*is*p*ra*c*tic*a*li*d*e*a*sab*out**s*u*ch**a**m*et*h*" +
        "od*t*heB*a*con*i*anmeth*o*dd*i*dno*t*have*a*l*o*n*g**la*s*t*ing*i*nfluen*c*e*th*e*g*e*ne*ral*i*dea*of**t*" +
        "heimp*o*rta*n*ceandpos*s*i*b*il*it*yo*f*as*c*ept*i*calmethodologymakesBaconthefatherofthescientificmethod" +
        "Thismethodwasanewrhetoricalandtheoreticalframeworkforsciencethepracticaldetailsofwhicharestillcentralinde" +
        "batesaboutscienceandmethodology"

fun main() {
    var italics = false;
    for (ch in cipherText) {
        if (ch == '*') {
            italics = !italics
            continue
        }
        print(if (italics) '1' else '0')
    }
}