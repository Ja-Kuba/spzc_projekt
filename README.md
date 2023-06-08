# SPZC PROJEKT


## SNIFFER


``` bash
pip3 install scapy
```
For Windows scapy needs [npcap](https://npcap.com/) to work



## Some useful data
### Protocols
Protocols numbers specification: 
https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml

- 6 **TPC**
- 17 **UDP**

## References:
 * Jung, Jaeyeon, et al. "Fast portscan detection using sequential hypothesis 
   testing." IEEE Symposium on Security and Privacy, 2004. Proceedings. 2004. 
   IEEE, 2004.




# Port Scan detection

## Statistical method

**based on article**: \
J. Jung, V. Paxson, A. W. Berger, H. Balakrishnan, *"Fast Portscan Detection Using Sequential Hypothesis Testing"* 

- TCP
- single to many type of attack

#### solution base ideas
TRW (Threshold Random Walk) 
TRW requires a much smaller number of connection attempts (4 or 5 in practice) to detect malicious activit


how quickly after the initial onset of activity can we determine with high probability that a series
of connections reflects hostile activity? Note that “quickly”
here is in terms of the amount of subsequent activity by the
scanner: the activity itself can occur at a very slow rate, but
we still want to nip it in the bud, i.e., detect it before it
has gone very far; and, ideally, do so with few false positives. The algorithm we develop, Threshold Random Walk
(TRW), can generally detect a scanner after 4 or 5 connection attempts, with high accuracy.


 However, our analysis of the sites’ connection logs revealed a sharp distinction between the activity of apparently benign hosts and
malicious hosts simply in terms of the proportion of their
connections that are successfully established, and so our final algorithm has the highly desirable properties that (1) it
does not require training, and (2) it does not require reparameterization when applying it at different sites.


**which features alg uses**
- timestamp of initiation
- duration of connection
- ultimate state(succes, rejected, unanswered)
- application protocol
- volum of data (each direction)
- local host
- remote host


**HOW it works**
`inactive_pct` -the percentage of the local hosts
that a given remote host has accessed for which the connection attempt failed (was rejected or unanswered

`known_bad` - hosty oznaczone jako zle - filtrowane już przez firewall



On the other hand, we see that in both cases, the remainder are sharply divided into two extreme sets—either
0% inactive pct, or 100% inactive_pct

**remainder hosts with  80% inactive pct are potentially benign**



skanery mają większe pstwo laczenia do nieistniejacych hostow - na podstawie tego wprowadzono usprawnienie majace na celu redukcje obserwowanych polaczen

In the previous section, we showed that one of the main
characteristics of scanners is that they are more likely than
legitimate remote hosts to choose hosts that do not exist
or do not have the requested service activated, since they
lack precise knowledge of which hosts and ports on the target network are currently active. Based on this observation,
we formulate a detection problem that provides the basis
for an on-line algorithm whose goal is to reduce the number of observed connection attempts (compared to previous
approaches) to flag malicious activity, while bounding the
probabilities of missed detection and false detectio


$r$ - remote host $Y_i$ wskaźnik czy pierwsze połączenie z $r$ do $i$-tego hosta w sieci się powiodło

$$
Y_i = \left\{\begin{matrix}
0 & if\:first\:connection\:succed\\ 
1 & if\:first\:connection\:failed
\end{matrix}\right.
$$


**Dwie hipotezy**
- $H_0$ - czy $r$ jest BENIGN
- $H_1$ - czy $r$ jest skanerem


$$
Y_i | H_j  \:\: i=1,2...
$$

rozkład Bernoulli'ego
