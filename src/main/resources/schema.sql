CREATE TABLE IF NOT EXISTS public.users (
    id SERIAL PRIMARY KEY,
    username TEXT NOT NULL,
    PASSWORD TEXT NOT NULL
);



-- drop table public.users;


-- select * from public.users;