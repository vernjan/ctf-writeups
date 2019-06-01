# 04 - Disco 2

*This year, we dance outside, yeaahh! See [here](https://hackyeaster.hacking-lab.com/hackyeaster/challenges/disco2/disco2.html).*

---

This is how the scene rendered in 3D looked like

![start.png](start.png)

At first, I was digging in [theRealBeat.mp3](theRealBeat.mp3) which was playing in the background but it was
a dead end.

Then I downloaded the sources to my local machine and start modifying it:

- I felt I should somehow take a look inside of the ball.
```
controls.minDistance = 50; // Was 500
```
![inside-the-ball.png](inside-the-ball.png)

Bingo, now it's time to make a nice readable QR code of out it ..


- Filter out the mirrors on the surface of the ball to get clean background.
  The trick is that the mirrors forming QR code are *Integers*.
```
for (var i = 0; i < mirrors.length; i++) {
  var m = mirrors[i];
  // ..
  if (Number.isInteger(m[0]) && Number.isInteger(m[1]) && Number.isInteger(m[2])) {   
    scene.add(mirrorTile);
  }
}
```
![no-mirrors-on-the-ball.png](no-mirrors-on-the-ball.png)


- Comment out the line where mirrors are rotated to look at the center.
```
//mirrorTile.lookAt(center);
```

![no-look-at-center.png](no-look-at-center.png)


-  Make the ball bigger.
```
var geometry = new THREE.SphereBufferGeometry(800.0, 48, 24); // Was 400.0
```

![bigger-ball.png](bigger-ball.png)


- Remove texture from the mirrors.
```
sphereMaterial = new THREE.MeshLambertMaterial({
  //envMap : textureCube
});
```
![no-texture.png](no-texture.png)


- Invert colors, crop and here is the final result:

![final.png](final.png)