drop database if exists cves;
create database cves;
use cves;
drop table if exists notified;
create table notified (
    id char(50),
    modDate char(50)
);
