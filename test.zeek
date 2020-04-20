# Copyright 2020 Nosaj Ux
#
# This file may be a fail rule file. Be careful while using.
global resp_table: table[addr] of count = table();
global gfw_table: table[addr] of count = table();
global normal_table: table[addr] of count = table();
global url_table: table[addr] of set[string] = table();
global orig_addr: set[addr];
global cur_time: time = current_time();
global start_time: time = current_time();
global inter: interval = 0sec;
global used_time:interval = current_time() - cur_time;

event zeek_init()
{
	print "Current time: ";
	print cur_time;
}

event http_reply(c: connection, version: string, code: count, reason: string)
{
    local url = to_lower(c$http$host + c$http$uri);
    inter += current_time() - cur_time;
    cur_time = current_time();
    if(!(c$id$orig_h in resp_table))
    {
        add orig_addr[c$id$orig_h];
        resp_table[c$id$orig_h] = 1;

        url_table[c$id$orig_h] = set(url);

        if(code == 404)
        {
            gfw_table[c$id$orig_h] = 1;
        }
        else
        {
            gfw_table[c$id$orig_h] = 0;
        }
    }
    else
    {
        if(!(to_lower(c$http$uri) in url_table[c$id$orig_h]))
        {
            add url_table[c$id$orig_h][c$http$uri];
        }

        resp_table[c$id$orig_h] += 1;
        if(code == 404)
        {
            gfw_table[c$id$orig_h] += 1;
        }
    }
    if(inter >= 10min)
    {
        for(i in orig_addr)
        {
            if(gfw_table[i] > 2)
            {
                if(gfw_table[i] / resp_table[i] > 0.2)
                {
                    if(|url_table[i]| / gfw_table[i] > 0.5)
                    {
                        print(addr_to_uri(i) + " is a scanner with ");
                        print(|url_table[i]|);
                        print(" scan attempts on ");
                        print(|gfw_table[i]|);
                        print(" urls. ");
                    }
                }
            }
        }
        inter = 0sec;
    }
}

event zeek_done() 
{
    inter = current_time() - start_time;
    print("Time used: ");
    print(inter);
}
