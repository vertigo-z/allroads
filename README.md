<img align="center" width="100%" height="100%" src="img/allroads.png" alt="allroads interface">
<img align="center" width="100%" height="100%" src="img/allroads_white.png" alt="allroads light mode">


---
<p>allroads</p>

latest working version. 
<br/>
<sup>ported from python to rust.</sup>

features:
- quarterly roadmap tracking. add and remove quarters as needed
- color coded tasks/features with descriptions
- 4 stages of development (planned, developing, testing, and completed)
- unified sqlite3 roadmap storage with optional AES database encryption
- option to store database encryption key in keychain
- move tasks up and down, and between quarters
- saved in .json format
- completely redone, clean, rust based ui

compiling:
```
cd allroads && cargo build --release
```
