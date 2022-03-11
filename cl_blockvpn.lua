Citizen.CreateThread( function()
    TriggerEvent( "chat:addSuggestion", "/whitelistip", "Temporarily whitelist an IP from being blocked by the VPN blocker.", {
        { name = "IP", help = "IP to whitelist." }
    } )
end )