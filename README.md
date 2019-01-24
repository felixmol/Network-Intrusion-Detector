# PFE SSR - Monitoring réseau dans un environnement SDN

PFE SSR (NET5535) 2018-2019 - Télécom SudParis
Félix Molina, Erwan Goarguer - Grégory Blanc, Mustafizur Shahid

## Contexte
Le paradigme *Software-Defined Networking* (SDN) permet la gestion centralisée du 
réseau. Les réseaux du futur, en particulier les réseaux IoT (*Internet of 
Things*), seront portés par ce paradigme réseau. Afin d'assurer la sécurité de 
ces réseaux, des systèmes de détection d'intrusion (IDS) doivent y être 
déployés. Typiquement, un IDS est déployé au niveau du contrôleur SDN. Lorsque 
l'IDS détecte une attaque, il instruit le contrôleur à mettre à jour les tables
de flux (*flow tables*) des commutateurs du réseau. 
Dans ce projet, nous nous intéressons aux IDS fonctionnant par apprentissage 
automatique (*machine learning*) des flux réseau. Ces IDS sont capables 
d'extraire des caractéristiques (*features*) du trafic réseau (p. ex., taille 
des paquets, durée des sessions, etc.) afin de les fournir en entrée à un 
algorithme de détection d'anomalies. L'extraction de ces *features* peut 
s'avérer très difficile dans un environnement SDN. Aussi, ce projet se propose
de concevoir et implémenter un extracteur de caractéristiques réseau temps réel
capable de fonctionner dans un environnement SDN.
Deux architectures sont proposées: 
* l'une sépare la collecte du trafic du commutateur;
* l'autre intègre la collecte sur le commutateur en utilisant le langage P4.

## Références
[Langage P4](https://p4.org/)

## Livrables attendus
* implémentation de prototypes
* rapport
