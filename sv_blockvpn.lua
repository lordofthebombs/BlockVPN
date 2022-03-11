-- Config variables for GetIPIntel
local owner_email = ""
local kick_threshhold = 0.99                                                    -- 0.99 is the recommended threshold according to the documentation
local flags = "b"                                                               -- The flag used by GetIPIntel to determing the strictness of the API. More info in https://getipintel.net/free-proxy-vpn-tor-detection-api/#optional_settings

-- Config variables for IPHub
local iphub_key = ""        -- Key from my own account, probably will be moved to predator's dev account when live
local block_code = 1                                                            -- 1 is recommended for most VPN's and proxies
local iphub_request_headers = { ["X-Key"] = iphub_key }

-- Config variables for IPQualityScore
local ipscore_key = ""                          -- This key is currently from my own account, probably will be moved to predator's dev account when live
local ipscore_threshhold = 85                                                   -- The value that determines how likely an IP is used for fraud
local strictness_level = "1"                                                    -- How strict the checks are in IPQualityScore. Levels are 0, 1, 2, and 3

-- Global variables
local kick_reason = "\n🛑 We've detected that you are potentially using a proxy or VPN. Please disable the proxy or VPN to play on the server.\n\nCurrent IP: "
local days = 30
local days_to_seconds = 86400                                                   -- Converts days into seconds
local cooldown = days_to_seconds * days                                         -- Days in seconds for how long an entry is valid for
local ip_regex = "(% *%d+% *%.% *%d+% *%.% *%d+% *%.% *%d+% *)"

-- Whitelisted IPs
local bypass_vpn_check = {
    [ "127.0.0.1" ] = true,
    [ "72.11.12.219" ] = true,
    [ "65.254.155.74" ] = true,
}

local temp_bypass = {}

-- Utility function
function pretty_print(msg)
    print( "[Predator BlockVPN] " .. msg )
end

-- Function to insert entries into the database
function insert_connected_user(ip, getipintel_result, getipintel_score, iphub_result, ipscore_score, ipscore_result, ipscore_json, predator_result, is_bad_ip)
    MySQL.Async.execute("INSERT INTO `connected_users` (ip_address, getipintel_result, getipintel_score, iphub_result, ipscore_score, ipscore_result, ipscore_json, predator_result, is_bad_ip) VALUES (@ip_address, @getipintel_result, @getipintel_score, @iphub_result, @ipscore_score, @ipscore_result, @ipscore_json, @predator_result, @is_bad_ip)",
        {
            ["ip_address"] = ip,
            ["getipintel_result"] = getipintel_result,
            ["getipintel_score"] = getipintel_score,
            ["iphub_result"] = iphub_result,
            ["ipscore_score"] = ipscore_score,
            ["ipscore_result"] = ipscore_result,
            ["ipscore_json"] = ipscore_json,
            ["predator_result"] = predator_result,
            ["is_bad_ip"] = is_bad_ip,
        },
        function()
            pretty_print("Added " .. ip .. " into the connected_users table.")
        end
    )
end


-- Adds in deffered connections to the database in the deffered_connections table
function insert_deffered_connection(ip, getipintel_result, iphub_result, ipscore_result, predator_result)
    MySQL.Async.execute("INSERT INTO `deffered_connections` (ip_address, getipintel_result, iphub_result, ipscore_result, predator_result) VALUES (@ip_address, @getipintel_result, @iphub_result, @ipscore_result, @predator_result)",
        {
            ["ip_address"] = ip,
            ["getipintel_result"] = getipintel_result,
            ["iphub_result"] = iphub_result,
            ["ipscore_result"] = ipscore_result,
            ["predator_result"] = predator_result
        },
        function()
            pretty_print("Added " .. ip .. " into the deferred_connections table.")
        end
    )
end


-- Runs the check to see if IPHub data flags the data as a potential VPN/Proxy
function iphub_check(data)
    local extracted_data = json.decode(data)
    if extracted_data["block"] == block_code then
        return true
    else
        return false
    end
end


-- Checks to see if the connecting IP is a bad IP
function check_if_bad_ip(ip, defer)
    MySQL.Async.fetchAll("SELECT ip_address, is_bad_ip, entry_date FROM `connected_users` WHERE ip_address = @ip_address ORDER BY entry_date DESC LIMIT 1", {["ip_address"] = ip}, function(result)
        local out_of_date
        local is_bad_ip
        
        -- Doing this check since I don't understand exception and error handling in lua
        if result[1] ~= nil then
            out_of_date = os.time() - (result[1]["entry_date"] / 1000) > cooldown           -- Dividing result time by 1000 because it's in miliseconds. So now all time stuff is converted to seconds
            is_bad_ip = result[1]["is_bad_ip"]
        end

        if result[1] == nil then 
            pretty_print("Analyizing IP as it is not stored in the database.")
            analyze_ip(ip, defer)
        elseif is_bad_ip and not out_of_date then
            pretty_print("Verified IP against database, IP returned as flagged.")
            defer.done(kick_reason .. ip)
        elseif not is_bad_ip and not out_of_date then
            pretty_print("Verified IP against database, IP returned as not flagged.")
            defer.done()
        elseif out_of_date then
            pretty_print("Analyizing IP as it is out of date in the database.")
            analyze_ip(ip, defer)
        end
    end)
end


-- Runs an analysis on the given IP address. To be run if the specified IP is not already in the database
function analyze_ip(ip, defer)
    -- IPHub check
    local iphub_success, iphub_result = false, false
    PerformHttpRequest("http://v2.api.iphub.info/ip/" .. ip, function(status_code, result, headers)
        iphub_success = true
        if iphub_check(result) then
            iphub_result = true
            pretty_print("IPHub has flagged the IP " .. ip)
        end
    end, "GET", "", iphub_request_headers)


    -- GetIPIntel check
    local getipintel_success, getipintel_result = false, false
    local getipintel_score = -1
    PerformHttpRequest("http://check.getipintel.net/check.php?ip=" .. ip .. "&contact=" .. owner_email .. "&flags=" .. flags, function(status_code, result, headers)
        if result == nil then print("Failed to connect to GetIPIntel.") return end
        local api_result = tonumber(result)
        if api_result == nil then return end

        if api_result == -5 then
            pretty_print("ERROR-GetIPIntel: GetIPIntel seems to have blocked the connection with error code 5 (Either incorrect email, blocked email, or blocked IP. Try changing the contact email)")
        elseif api_result == -6 then
            pretty_print("ERROR-GetIPIntel: A valid contact email is required!")
        elseif api_result == -4 then
            pretty_print("ERROR-GetIPIntel: Unable to reach database.")
        elseif api_result >= kick_threshhold then
            pretty_print("GetIPIntel has scored " .. ip .. " as: " .. api_result)
            getipintel_result = true
            getipintel_success = true
        end
        getipintel_score = api_result
    end, "GET", "", {})


    -- IPQualityScore check
    local ipscore_success, ipscore_result = false, false
    local ipscore_score = -1
    local ipscore_json
    PerformHttpRequest("https://ipqualityscore.com/api/json/ip/" .. ipscore_key .. "/" .. ip .. "?strictness=" .. strictness_level .. "&allow_public_access_points=false", function(status_code, result, headers)
        if result == nil then pretty_print("Failed to connect to IPQualityScore.") return end
        ipscore_json = result
        local success, data1, data2 = ipscore_check(result)
        if success then ipscore_success = true end
        ipscore_score = data2
        if data1 then
            ipscore_result = true
            pretty_print("IPQualityScore has scored " .. ip .. " as: " .. ipscore_score)
        end
    end, "GET", "", {})


    -- API success check
    local max_count, count = 50, 0
    while not (iphub_success and getipintel_success and ipscore_success) do
        if count == max_count then
            pretty_print("Allowing IP: " .. ip .. ", due to lack of API response.") 
            break
        end
        count = count + 1
        Wait(100)
    end

    -- If any of these results are true, refuse the connection from the player
    -- Prints all results if player's connection is refused
    if (iphub_result or getipintel_result or ipscore_result) then
        pretty_print("Refusing connection to: " .. ip .. ", detected as a potential proxy or VPN.")
        defer.done(kick_reason .. ip)
        insert_deffered_connection(ip, getipintel_result, iphub_result, ipscore_result, false)    -- predator_result set to false since it doesn't exist yet
        insert_connected_user(ip, getipintel_result, getipintel_score, iphub_result, ipscore_score, ipscore_result, ipscore_json, false, true)      -- IP is bad when deffered
    else
        insert_connected_user(ip, getipintel_result, getipintel_score, iphub_result, ipscore_score, ipscore_result, ipscore_json, false, false)     -- IP is not bad when not defferred
        defer.done()
    end
end


-- Checks the IP using the IPQualityScore API and returning the results
function ipscore_check(data)
    local extracted_data = json.decode(data)
    if ( extracted_data["fraud_score"] > ipscore_threshhold ) or extracted_data["vpn"] or
    extracted_data["tor"] or extracted_data["active_vpn"] or extracted_data["active_tor"] then
        return extracted_data["succes"], true, extracted_data["fraud_score"]
    else
        return extracted_data["succes"], false, extracted_data["fraud_score"]
    end
end

-- Currently only kicks based off of IPHub result, I have yet to implement a check using GetIPIntel
AddEventHandler("playerConnecting", function(player_name, set_kick_keason, deferrals)
    local src = source
    local def = deferrals

    local connected_ip = GetPlayerEndpoint(src)
    def.defer()
    -- According to https://docs.fivem.net/docs/scripting-reference/events/list/playerConnecting/ I have to put a Wait here
    Wait(0)
    def.update("Checking player connection status.")

    Wait(500)
    if IsPlayerAceAllowed(src, "predatorBlockVPN:bypass") then 
        pretty_print( GetPlayerName( src ) .. " has bypassed checks due to bypass permission." ) 
        def.done()
        return 
    end

    if bypass_vpn_check[ connected_ip ] then
        pretty_print( GetPlayerName( src ) .. " has bypassed checks due to their IP: " .. connected_ip .. " being whitelisted." ) 
        def.done() 
        return 
    end

    if temp_bypass[ connected_ip ] then
        pretty_print( GetPlayerName( src ) .. " has bypassed checks due to their IP: " .. connected_ip .. " being temporarily whitelisted." ) 
        def.done() 
        return 
    end 

    -- Checks if the connecting player has a bad IP address. It's where the brains of this whole thing is
    check_if_bad_ip(connected_ip, def)
end)

RegisterCommand("whitelistip", function(source, args, rawCommand)
    if not args[ 1 ] then 
        TriggerClientEvent("chat:addMessage", source, {
            color = {255,0,0},
            multiline = true,
            args = {"Server", "You have failed to enter the IP to temporarily whitelist."}
        })
        return
    else
        if string.find( args[ 1 ], ip_regex ) then
            temp_bypass[ tostring( args[ 1 ] ) ] = true
            TriggerClientEvent("chat:addMessage", source, {
                color = {255,0,0},
                multiline = true,
                args = {"Server", "You have temporarily whitelisted the IP: " .. tostring( args[ 1 ] )}
            })
        else
            TriggerClientEvent("chat:addMessage", source, {
                color = {255,0,0},
                multiline = true,
                args = {"Server", "You did not enter a valid IP."}
            })
        end
    end
end, true)
