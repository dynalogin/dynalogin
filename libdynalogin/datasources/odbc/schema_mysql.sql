
-- This table stores the users
-- It is the only table that is really essential
-- Other tables can be created for logging, management functions, etc

CREATE TABLE dynalogin_user (
  id int primary key auto_increment,
  userid varchar(32) not null unique,
  scheme varchar(16) not null,
  secret varchar(32) not null,
  counter bigint unsigned not null,
  failure_count int not null,
  locked int not null,
  last_success datetime,
  last_attempt datetime,
  last_code varchar(32),
  password varchar(32)
);


  
