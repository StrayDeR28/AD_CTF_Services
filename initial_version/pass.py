# для отладочной херни

INSERT INTO friends (id, friend1_login, friend2_login, is_approved)
VALUES (13, 'bob', 'artem', false), 
		(14, 'bobs', 'lexa', false),
		(15, 'bob', 'dfs', false);
INSERT INTO postcards (id, sender_login, receiver_login, text, is_private) 
VALUES (7, 'charlie', 'lexa', 'Привет! ++  ', false), 
(8, 'charlie', 'dfs', 'Привет! ++  ', false);

SELECT * FROM public.user_last_seen
-- user_last_seen friends postcards

DELETE FROM postcards
WHERE id NOT IN (
    SELECT id FROM postcards
    ORDER BY id
    LIMIT 6
);
-- user_last_seen friends 12 postcards 6