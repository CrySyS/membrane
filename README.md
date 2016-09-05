# Membrane: A Posteriori Detection of Malicious Code Loading by Memory Paging Analysis

Membrane is a memory forensics tool to detect code loading behavior by stealthy malware.
Instead of trying to detect the code loading itself, we focus on the changes
it causes on the memory paging of the Windows operating system. As
our method focuses on the anomalies caused by code loading, we are
able to detect a wide range of code loading techniques. Our results indicate
that we can detect code loading malware behavior with 86-98%
success in most cases, including advanced targeted attacks. Our method
is generic enough and hence could significantly raise the bar for attackers
to remain stealthy and persist for an extended period of time.

**Corresponding article:**

G. Pék, Zs. Lázár, Z. Várnagy, M. Félegyházi, L. Buttyán, [Membrane: A Posteriori Detection of Malicious Code Loading by Memory Paging Analysis (Accepted paper),](http://www.crysys.hu/~pek/pubs/Pek+16ESORICS.pdf), ESORICS, Heraklion, Greece, 2016. 


## Source

This repository contains the memory traversal part of the Membrane source code. Please find the traditional Volatility extension in the `membrane` directory.
As snapshot creation can be a heavy-duty operation, we further designed and implemented a live monitoring version of Membrane called
Membrane Live by extending a virtual machine introspection-based malware analysis tool called [DRAKVUF](https://github.com/tklengyel/drakvuf).


