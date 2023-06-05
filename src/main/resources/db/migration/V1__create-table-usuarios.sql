create table usuarios(
	id bigint not null auto_increment,
	nombre varchar(100) not null,
	apellido varchar(100) not null,
	rol varchar(100) not null,
	email varchar(100) not null unique,
	clave varchar(100) not null,
	primary key(id)
)