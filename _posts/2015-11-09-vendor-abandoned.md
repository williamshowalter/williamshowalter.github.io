---
layout: post
title: Vendor Abandoned - Finding vulnerabilities in consumer devices
tags: [vulnerabilities, exploits, seagate, blackarmor]
date: 2015-11-09T12:52:00.573882-06:00
comments: true
---
# A Case Study on the Seagate Blackarmor NS440 NAS

## Background

I've been exploring the functionality of my rather outdated Seagate NAS recently, partially to sate my own curiosity about the NAS, and partially for a graduate reasearch project. I presented my findings at the BSidesJackson conference on November 7th, 2015, and am posting my slides along with the accompanying white paper.

## Abstract

This white paper aims to discuss the commonly poor security of consumer and small-business grade digital devices, and the choices made by their manufactures that brings about that situation. It is the case that many vendors build their products without regard to a security lifecycle. A case study is provided on discovering and creating exploits targeting the Seagate Blackarmor NS440 NAS, specifically detailing the methodology and results of such efforts. Vendors build networked devices using already outdated open source software and discontinue support for one model as soon as the next is released. This is especially true for companies whose primary business lies outside these products. Network attached storage devices and home security cameras are common examples that are used by both consumers and small businesses.
Seagate’s network attached storage devices fall into this categorization. Seagate’s core business is hard drive manufacture, but the company also has products in both the network and cloud storage markets. Product support is frequently discontinued soon after new models are released, and devices remain in production use for years without any software maintenance. Additionally, the software on the devices is a combination of outdated and custom built, neither quality typically being beneficially for security. The presented case study shows a number of potential vulnerabilities in the Seagate Blackarmor NS440, ranging from binary exploitation to command injection through cross-site request forgery attacks, and works through the process of developing a working exploit against the device. These methodologies can be applied to other innocuous- seeming devices and demonstrate a much greater attack surface than would generally be suspected.

## Downloads

#####[Download White Paper]({{ site.url }}/assets/Vendor_Abandoned.pdf)

#####[Download Slides from BSidesJackson]({{ site.url }}/assets/BSides2015.pdf)