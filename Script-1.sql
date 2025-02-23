--------------------------------------------------
-- Use pgcrypto extension functions to validate the JWT signature (pos. 3)

create or replace function decode_jwt(jwt text, secret text, signing_method text)
returns table (pos integer, contents text) language sql immutable as
$$
	with parts as (
	  select * from regexp_split_to_table(jwt, '\.') with ordinality as t(x, pos)
	)
	select pos,
	  case when pos = 3 then x
	  else convert_from(decode(rpad(translate(x, '-_', '+/'), 4*((length(x)+3)/4), '='), 'base64'), 'utf-8')
	  end
	from parts order by pos;
$$;


CREATE EXTENSION IF NOT EXISTS pgcrypto;

create or replace function verify_jwt(jwt text, secret text, signing_method text)
returns boolean language plpgsql as
$$
declare
    head text;
    payload text;
    signature text;
    signing_input text;
    computed_sig bytea;
    computed_sig_b64 text;
begin
    -- Extract parts using your decode_jwt function or similar logic
    with parts as (
      select * from regexp_split_to_table(jwt, '\.') with ordinality as t(x, pos)
    )
    select
      max(case when pos = 1 then x end),
      max(case when pos = 2 then x end),
      max(case when pos = 3 then x end)
    into head, payload, signature
    from parts;

    if head is null or payload is null or signature is null then
      raise exception 'Invalid JWT structure';
    end if;

    signing_input := (head || '.' || payload);
--	raise notice '%', signing_input;

    -- Compute the HMAC using the secret.
	if signing_method = 'sha256' or signing_method = 'HS256' then
    	computed_sig := hmac(signing_input, secret, 'sha256');
	elsif signing_method = 'sha512' or signing_method = 'HS512' then
		computed_sig := hmac(signing_input, secret, 'sha512');
	else
		raise exception 'Unsupported signing method: %', signing_method;
	end if;

    -- Convert computed signature to standard base64.
    computed_sig_b64 := encode(computed_sig, 'base64');
    
    -- Convert to URL-safe base64: replace characters and remove padding.
    computed_sig_b64 := translate(computed_sig_b64, '+/', '-_');
    computed_sig_b64 := regexp_replace(computed_sig_b64, '=+$', '');
    computed_sig_b64 := regexp_replace(computed_sig_b64, '\n', ''); -- there was somehow a new line while I was testing the function
    
    -- Compare the computed signature with the provided one.
	raise notice 'Computed signature: %', computed_sig_b64;
	raise notice 'Real signature: %', signature;
    return computed_sig_b64 = signature;
end;
$$;


-- Unit test -------------------------------------

select * from decode_jwt('eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiJ9.eyJpc3MiOiJPbmxpbmUgSldUIEJ1aWxkZXIiLCJpYXQiOjE3NDAyMTc2NDksImV4cCI6MTc3MTc1MzY0OSwiYXVkIjoid3d3LmV4YW1wbGUuY29tIiwic3ViIjoianJvY2tldEBleGFtcGxlLmNvbSIsIm5hbWUiOiJKb2huIERvZSIsInNvbWVfaW50IjoiMTk4MjA4OSJ9.mI1J5XgumcHBLMCH8gq4-znIwJ2V_LY8XntEU5ccdS7MzMcvtNfExBEb-swvkiTNbEzgyAu-lcwo6u3kowmhTQ');
select verify_jwt(
  'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiJ9.eyJpc3MiOiJPbmxpbmUgSldUIEJ1aWxkZXIiLCJpYXQiOjE3NDAyMTc2NDksImV4cCI6MTc3MTc1MzY0OSwiYXVkIjoid3d3LmV4YW1wbGUuY29tIiwic3ViIjoianJvY2tldEBleGFtcGxlLmNvbSIsIm5hbWUiOiJKb2huIERvZSIsInNvbWVfaW50IjoiMTk4MjA4OSJ9.mI1J5XgumcHBLMCH8gq4-znIwJ2V_LY8XntEU5ccdS7MzMcvtNfExBEb-swvkiTNbEzgyAu-lcwo6u3kowmhTQ',
  'some_key', 'sha512'
);
