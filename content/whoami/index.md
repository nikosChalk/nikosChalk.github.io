---
title: "About me"
showDate: false
---
<style>
.single-row {
  margin-bottom: 0.37em;
}
.single-row input[type="checkbox"] {
  display: none;
}

.content {
  max-height: 0;
  overflow: hidden;
  -webkit-transition: max-height 250ms ease-in-out;
  -moz-transition: max-height 250ms ease-in-out;
  -o-transition: max-height 250ms ease-in-out;
  transition: max-height 250ms ease-in-out;
  /* background-color: var(--default_hl_bg); */
}

.moddedfa {
  margin-right: 1em;
  /* margin-left: 1em; */
  -webkit-transform: rotate(-90deg);
  -moz-transform: rotate(-90deg);
  -o-transform: rotate(-90deg);
  transform: rotate(-90deg);
  -webkit-transition: -webkit-transform 250ms ease-in-out;
  -moz-transition: -moz-transform 250ms ease-in-out;
  -o-transition: -o-transform 250ms ease-in-out;
  transition: transform 250ms ease-in-out;
}

.opener:checked+label+div.content {
  display: block;
  max-height: 350px;
}

.opener:checked+label .moddedfa {
  -webkit-transform: rotate(0) translate(0, -3px);
  -moz-transform: rotate(0) translate(0, -3px);
  -o-transform: rotate(0) translate(0, -3px);
  transform: rotate(0) translate(0, -3px);
}

.content ul {
  margin-top: 0px;
}
</style>

Hi! I am **Nikolaos Chalkiadakis** and I work in the Application Security field. I have extensive knowledge and work experience in **Mobile Security**, **Android internals**, **reverse engineering**, **binary exploitation**, and **kernel development**. I usually post about low-level exploitation with the goal to spread knowledge and to maybe help someone learn something new.

Occasional [CTF player](https://github.com/nikosChalk/ctf-writeups) (pwn/rev/web)
Intense <img src="/coffee.png" alt="coffee.png" style="display: inline-block; margin-bottom: -2pt; margin-left: -2pt;" width="18pt"/> consumer, addicted to ⛷️

---

### Education

<div class="single-row">
  <input name="collapsable" type="checkbox" id="col-1" class="opener"/>
  <label for="col-1">
    <i class="fa fa-sort-desc moddedfa"></i><span>2023 | M.Sc. in Computer Science <b>9.00/10.0</b> | VU Amsterdam, UvA &nbsp; (Netherlands)</span>
  </label>
  <div class="content">
    <ul>
      <li><b>Thesis</b>: SpaceForce: Spatial and partially temporal heap protection with tagged buffed pointers @ <a href="https://www.vusec.net" target="_blank" rel="noopener noreferrer"><b>VUSec</b></a></li>
      <li>Postgraduate <b>scholarship</b> <q>VU Fellowship Programme (VUFP)</q></li>
      <li>Followed the <b>Computer Systems Security track</b></li>
      <li>Noteworthy attended courses:
        <ul>
          <li><b>Computer and Network Security</b></li>
          <li><b>Binary and Malware Analysis</b></li>
          <li><b>Hardware Security</b></li>
          <li><b>Advanced Operating Systems</b></li>
          <li><b>Software Containerization</b></li>
        </ul>
      </li>
    </ul>
  </div>
</div>

<div class="single-row" style="margin-bottom: 0px;">
  <input name="collapsable" type="checkbox" id="col-2" class="opener"/>
  <label for="col-2">
    <i class="fa fa-sort-desc moddedfa"></i><span>2019 | B.Sc. in Computer Science <b>9.45/10.0</b> | University of Crete (Greece)</span>
  </label>
  <div class="content">
    <ul>
      <li><b>Thesis</b>: The Million Dollar Handshake: Secure and Attested Communications in the Cloud @ <a href="https://www.ics.forth.gr/discs" target="_blank" rel="noopener noreferrer"><b>DiSCS Lab - FORTH-ICS</b></a></li>
      <li>Undergraduate <b>scholarship</b> <q>Stelios Orfanoudakis</q></li>
      <li>Noteworthy attended courses:
        <ul>
          <li><b>Embedded Systems Lab</b></li>
          <li><b>Parallel Programming</b></li>
          <li><b>Principles of Distributed Computing</b></li>
        </ul>
      </li>
    </ul>
  </div>
</div>

<br/>

---

### Skills

<span class="inline-h4">Languages:</span> C, C++, x86_64 and aarch64 assembly, Java, Kotlin, smali, Python

<span class="inline-h4">Tooling:</span> Android stuff (apps, custom native tools, kernel modules, etc.), frida scripting, gdb scripting, Ghidra scripting, IDA, JEB, pwntools, angr, Intel PIN, Burp suite, Wireshark, Docker, QEMU, git
