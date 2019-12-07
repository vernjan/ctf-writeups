# HV19.06 bacon and eggs
![Bacon_vs_Parliament.jpg](bacon.jpg)

*F*ra*n*cis Baco*n* *w*a*s* *a*n E*ng*lish ph*i*l*os*o*p*her a*n*d *s*tat*e*sm*a*n w*h*o se*rve*d *a*s At*t*or*n*ey Gen*e*ral and as *L*or*d* *Ch*an*ce*l*l*or of *En*g*l*an*d*. Hi*s* *w*orks ar*e* c*red*it*e*d w*ith* d*e*ve*lo*pi*ng* *t*h*e* sci*e*nt*i*fic me*t*hod and re*m*ai*ned* in*fl*u*en*ti*al* th*rou*gh *t*he s*cien*tific *r*ev*o*l*u*ti*o*n.
*B*a*co*n h*as* *b*e*e*n ca*l*led *th*e *f*ath*e*r o*f* emp*iric*i*s*m. *Hi*s *wor*ks ar*g*ued for th*e* po*ssi*bi*li*t*y* of s*c*ie*n*tifi*c* *kno*wl*edg*e b*a*se*d* onl*y* u*p*on i*n*du*c*t*i*ve *r*ea*s*onin*g* *a*nd c*aref*u*l* o*bs*er*v*ation o*f* *e*v*e*nt*s* in *na*tur*e*. Mo*st* *i*mp*ort*an*t*l*y*, *he* a*rgue*d sc*i*en*c*e co*uld* *b*e *a*c*hi*eved by us*e* of a *s*ce*p*t*ical* a*nd* me*t*hod*i*ca*l* *a*pp*roa*ch wh*er*eby *s*cientist*s* ai*m* t*o* avo*i*d m*i*sl*ead*in*g* themsel*ve*s. *A*lth*oug*h *h*is *p*ra*c*tic*a*l i*d*e*a*s ab*out* *s*u*ch* *a* *m*et*h*od, *t*he B*a*con*i*an meth*o*d, d*i*d no*t* have *a* l*o*n*g*-*la*s*t*ing *i*nfluen*c*e, *th*e *g*e*ne*ral *i*dea *of* *t*he imp*o*rta*n*ce and pos*s*i*b*il*it*y o*f* a s*c*ept*i*cal methodology makes Bacon the father of the scientific method. This method was a new rhetorical and theoretical framework for science, the practical details of which are still central in debates about science and methodology.

Bacon was the first recipient of the Queen's counsel designation, which was conferred in 1597 when Elizabeth I of England reserved Bacon as her legal advisor. After the accession of James VI and I in 1603, Bacon was knighted. He was later created Baron Verulam in 1618 and Viscount St. Alban in 1621.
Because he had no heirs, both titles became extinct upon his death in 1626, at 65 years. Bacon died of pneumonia, with one account by John Aubrey stating that he had contracted the condition while studying the effects of freezing on the preservation of meat. He is buried at St Michael's Church, St Albans, Hertfordshire.
```
Born: January 22	     	 	   	   	 	       	     	  	  
Died: April 9   	  	 	    	  	      	   		  	  
Mother: Lady Anne   		 	   	   	      	  	      	  
Father: Sir Nicholas	 	      		    	    	  	  	      	      
Secrets: unknown      	 	  	 	    	    	   	       	  
```

---

I know [Bacon's cipher](https://en.wikipedia.org/wiki/Bacon%27s_cipher) so this was one was
easy for me. I copied the first paragraph with letters in italics from the [HTTP response](bacon.json) and
converted it into ones and zeros. I used a
[simple script](../../../src/main/kotlin/cz/vernjan/ctf/hv19/day06/Bacon.kt) to do the conversion.

This is the output:
```
100100000001101100110000001011010000101000100100100011101000100100000100000000100111001101000011010010011000000101110010011101001100111010001001000001000000001001110011011001100111001000111100000100101001010110011101000100011010001001000111101011011100001000000001001110011010001001000011110011100100100010100010010100100100001100011110101100100000011010010011000100111001110010111011110001001000111101011000000001000100101111011001000100110011100001100010000000010010100010010011100100000001101000111010010010001001010001111011110010010001000100000010010001000010101110100010000001011010110001000111000001000100000000101001100100100010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
```

Finally, I used https://www.dcode.fr/bacon-cipher for decryption:
```
SANTALIKESHISBACONBUTALSOTHISBACONTHEPASSWORDISHVXBACONCIPHERISSIMPLEBUTCOOLXREPLACEXWITHBRACKETSANDUSEUPPERCASEFORALLCHARACTERAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
```

The flag is `HV19{BACONCIPHERISSIMPLEBUTCOOL}` (I figured out I should add `19` myself)