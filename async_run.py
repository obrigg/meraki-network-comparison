__version__ = '1.0'
__author__ = 'Oren Brigg'
__author_email__ = 'obrigg@cisco.com'
__license__ = "Cisco Sample Code License, Version 1.1 - https://developer.cisco.com/site/license/cisco-sample-code-license/"


import meraki
import asyncio
import meraki.aio
from deepdiff import DeepDiff
from rich import print as pp
from rich.console import Console
from rich.table import Table


def SelectNetwork():
    # Fetch and select the organization
    print('\n\nFetching organizations...\n')
    organizations = dashboard.organizations.getOrganizations()
    organizations.sort(key=lambda x: x['name'])
    ids = []
    table = Table(title="Meraki Organizations")
    table.add_column("Organization #", justify="left", style="cyan", no_wrap=True)
    table.add_column("Org Name", justify="left", style="cyan", no_wrap=True)
    counter = 0
    for organization in organizations:
        ids.append(organization['id'])
        table.add_row(str(counter), organization['name'])
        counter+=1
    console = Console()
    console.print(table)
    isOrgDone = False
    while isOrgDone == False:
        selected = input('\nKindly select the organization ID you would like to query: ')
        try:
            if int(selected) in range(0,counter):
                isOrgDone = True
            else:
                print('\t[bold red]Invalid Organization Number\n')
        except:
            print('\t[bold red]Invalid Organization Number\n')
    # Fetch and select the network within the organization
    org_id = organizations[int(selected)]['id']
    print('\n\nFetching networks...\n')
    networks = dashboard.organizations.getOrganizationNetworks(org_id)
    networks.sort(key=lambda x: x['name'])
    ids = []
    table = Table(title="Available Networks")
    table.add_column("Network #", justify="left", style="green", no_wrap=True)
    table.add_column("Network Name", justify="left", style="green", no_wrap=True)
    counter = 0
    for network in networks:
        ids.append(network['id'])
        table.add_row(str(counter), network['name'])
        counter += 1
    console = Console()
    console.print(table)
    isNetDone = False
    while isNetDone == False:
        selected = input('\nKindly select the reference network you would like to compare other to: ')
        try:
            if int(selected) in range(0,counter):
                isNetDone = True
            else:
                print('\t[bold red]Invalid Organization Number\n')
        except:
            print('\t[bold red]Invalid Organization Number\n')
    return(networks, networks[int(selected)])


async def check_wireless_ssid(aiomeraki: meraki.aio.AsyncDashboardAPI, network: dict, reference_network: dict):
    if network['id'] == reference_network['id']:
        return(None)
    try:
        reference_ssids = await aiomeraki.wireless.getNetworkWirelessSsids(reference_network['id'])    
    except Exception as e:
        pp(f'[bold magenta]Some other ERROR: {e}')
    try:
        network_ssids = await aiomeraki.wireless.getNetworkWirelessSsids(network['id'])
    except Exception as e:
        pp(f'[bold magenta]Some other ERROR: {e}')
    # Removing the SSID number, to prevent alerting in case only numbering changed
    # Removing RADIUS servers' ID's as they will change between networks
    for i in range(len(reference_ssids)):
        del reference_ssids[i]['number']
        if 'radiusServers' in reference_ssids[i].keys():
            for j in range(len(reference_ssids[i]['radiusServers'])):
                del reference_ssids[i]['radiusServers'][j]['id']
    for i in range(len(network_ssids)):
        del network_ssids[i]['number']
        if 'radiusServers' in network_ssids[i].keys():
            for j in range(len(network_ssids[i]['radiusServers'])):
                del network_ssids[i]['radiusServers'][j]['id']
    diff = DeepDiff(reference_ssids, network_ssids, group_by='name', ignore_order=True)
    print_messages(network['name'], reference_network['name'], diff, "SSID")
    results[network['name']]['ssids'] = diff


async def check_wireless_rf_profiles(aiomeraki: meraki.aio.AsyncDashboardAPI, network: dict, reference_network: dict):
    if network['id'] == reference_network['id']:
        return(None)
    try:
        reference_profiles = await aiomeraki.wireless.getNetworkWirelessRfProfiles(reference_network['id'])    
    except Exception as e:
        pp(f'[bold magenta]Some other ERROR: {e}')
    try:
        network_profiles = await aiomeraki.wireless.getNetworkWirelessRfProfiles(network['id'])
    except Exception as e:
        pp(f'[bold magenta]Some other ERROR: {e}')
    diff = DeepDiff(reference_profiles, network_profiles, group_by='name', ignore_order=True)
    print_messages(network['name'], reference_network['name'], diff, "RF Profile")
    results[network['name']]['rf_profiles'] = diff


async def check_wireless_settings(aiomeraki: meraki.aio.AsyncDashboardAPI, network: dict, reference_network: dict):
    if network['id'] == reference_network['id']:
        return(None)
    try:
        reference_settings = await aiomeraki.wireless.getNetworkWirelessSettings(reference_network['id'])    
    except Exception as e:
        pp(f'[bold magenta]Some other ERROR: {e}')
    try:
        network_settings = await aiomeraki.wireless.getNetworkWirelessSettings(network['id'])
    except Exception as e:
        pp(f'[bold magenta]Some other ERROR: {e}')
    diff = DeepDiff(reference_settings, network_settings, ignore_order=True)
    print_messages(network['name'], reference_network['name'], diff, "wireless setting")
    results[network['name']]['wireless_settings'] = diff


async def check_wireless_l3_rules(aiomeraki: meraki.aio.AsyncDashboardAPI, network: dict, reference_network: dict):
    if network['id'] == reference_network['id']:
        return(None)
    reference_rules = []
    network_rules = []
    for i in range(15):
        try:
            rules = await aiomeraki.wireless.getNetworkWirelessSsidFirewallL3FirewallRules(reference_network['id'], i)
            for rule in rules['rules']:
                if 'ipVer' in rule.keys():
                    del rule['ipVer']
            reference_rules.append(rules)
        except Exception as e:
            pp(f'[bold magenta]Some other ERROR: {e}')
        try:
            rules = await aiomeraki.wireless.getNetworkWirelessSsidFirewallL3FirewallRules(reference_network['id'], i)
            for rule in rules['rules']:
                if 'ipVer' in rule.keys():
                    del rule['ipVer']
            network_rules.append(rules)
        except Exception as e:
            pp(f'[bold magenta]Some other ERROR: {e}')
    diff = DeepDiff(reference_rules, network_rules, ignore_order=True)
    print_messages(network['name'], reference_network['name'], diff, "wireless L3 rule")
    results[network['name']]['wireless_l3_rules'] = diff


async def check_wireless_l7_rules(aiomeraki: meraki.aio.AsyncDashboardAPI, network: dict, reference_network: dict):
    if network['id'] == reference_network['id']:
        return(None)
    reference_rules = []
    network_rules = []
    for i in range(15):
        try:
            reference_rules.append(await aiomeraki.wireless.getNetworkWirelessSsidFirewallL7FirewallRules(reference_network['id'], i))
        except Exception as e:
            pp(f'[bold magenta]Some other ERROR: {e}')
        try:
            network_rules.append(await aiomeraki.wireless.getNetworkWirelessSsidFirewallL7FirewallRules(network['id'], i))
        except Exception as e:
            pp(f'[bold magenta]Some other ERROR: {e}')
    diff = DeepDiff(reference_rules, network_rules, ignore_order=True)
    print_messages(network['name'], reference_network['name'], diff, "wireless L7 rule")
    results[network['name']]['wireless_l7_rules'] = diff


async def check_wireless_shaping_rules(aiomeraki: meraki.aio.AsyncDashboardAPI, network: dict, reference_network: dict):
    if network['id'] == reference_network['id']:
        return(None)
    reference_rules = []
    network_rules = []
    for i in range(15):
        try:
            reference_rules.append(await aiomeraki.wireless.getNetworkWirelessSsidTrafficShapingRules(reference_network['id'], i))
        except Exception as e:
            pp(f'[bold magenta]Some other ERROR: {e}')
        try:
            network_rules.append(await aiomeraki.wireless.getNetworkWirelessSsidTrafficShapingRules(network['id'], i))
        except Exception as e:
            pp(f'[bold magenta]Some other ERROR: {e}')
    diff = DeepDiff(reference_rules, network_rules, ignore_order=True)
    print_messages(network['name'], reference_network['name'], diff, "wireless shaping rule")
    results[network['name']]['wireless_shaping_rules'] = diff


async def check_switch_stp(aiomeraki: meraki.aio.AsyncDashboardAPI, network: dict, reference_network: dict):
    if network['id'] == reference_network['id']:
        return(None)
    try:
        reference_settings = await aiomeraki.switch.getNetworkSwitchStp(reference_network['id'])    
    except Exception as e:
        pp(f'[bold magenta]Some other ERROR: {e}')
    try:
        network_settings = await aiomeraki.switch.getNetworkSwitchStp(network['id'])
    except Exception as e:
        pp(f'[bold magenta]Some other ERROR: {e}')
    diff = DeepDiff(reference_settings, network_settings, ignore_order=True)
    print_messages(network['name'], reference_network['name'], diff, "STP setting")
    results[network['name']]['stp_settings'] = diff


async def check_switch_mtu(aiomeraki: meraki.aio.AsyncDashboardAPI, network: dict, reference_network: dict):
    if network['id'] == reference_network['id']:
        return(None)
    try:
        reference_settings = await aiomeraki.switch.getNetworkSwitchMtu(reference_network['id'])    
    except Exception as e:
        pp(f'[bold magenta]Some other ERROR: {e}')
    try:
        network_settings = await aiomeraki.switch.getNetworkSwitchMtu(network['id'])
    except Exception as e:
        pp(f'[bold magenta]Some other ERROR: {e}')
    diff = DeepDiff(reference_settings, network_settings, ignore_order=True)
    print_messages(network['name'], reference_network['name'], diff, "MTU setting")
    results[network['name']]['mtu_settings'] = diff


async def check_switch_acl(aiomeraki: meraki.aio.AsyncDashboardAPI, network: dict, reference_network: dict):
    if network['id'] == reference_network['id']:
        return(None)
    try:
        reference_settings = await aiomeraki.switch.getNetworkSwitchAccessControlLists(reference_network['id'])    
    except Exception as e:
        pp(f'[bold magenta]Some other ERROR: {e}')
    try:
        network_settings = await aiomeraki.switch.getNetworkSwitchAccessControlLists(network['id'])
    except Exception as e:
        pp(f'[bold magenta]Some other ERROR: {e}')
    diff = DeepDiff(reference_settings, network_settings, ignore_order=True)
    print_messages(network['name'], reference_network['name'], diff, "ACL")
    results[network['name']]['acls'] = diff


async def check_firmware(aiomeraki: meraki.aio.AsyncDashboardAPI, network: dict, reference_network: dict):
    if network['id'] == reference_network['id']:
        return(None)
    reference_firmware = {}
    network_firmware = {}
    try:
        reference_settings = await aiomeraki.networks.getNetworkFirmwareUpgrades(reference_network['id'])
        for product in reference_settings['products']:
            reference_firmware[product] = reference_settings['products'][product]['currentVersion']
    except Exception as e:
        pp(f'[bold magenta]Some other ERROR: {e}')
    try:
        network_settings = await aiomeraki.networks.getNetworkFirmwareUpgrades(network['id'])
        for product in network_settings['products']:
            network_firmware[product] = network_settings['products'][product]['currentVersion']['shortName']
    except Exception as e:
        pp(f'[bold magenta]Some other ERROR: {e}')
    diff = DeepDiff(reference_firmware, network_firmware, ignore_order=True)
    print_messages(network['name'], reference_network['name'], diff, "Firmware")
    results[network['name']]['firmware'] = diff


def parse_diff(diff) -> dict:
    result = {"added primaries": [],
              "removed primaries": [],
              "added secondaries": [],
              "removed secondaries": [],
              "changed values": []}
    if "dictionary_item_removed" in diff.keys():
        for item in diff['dictionary_item_removed']:
            primary = item[item.find('[')+2:item.find(']')-1]
            secondary = item[item.find('][')+3:item.find(']]')-1]
            if item.count("[") == 1:
                result['removed primaries'].append(primary)
            else:
                result['removed secondaries'].append((primary, secondary))
    if "dictionary_item_added" in diff.keys():
        for item in diff['dictionary_item_added']:
            primary = item[item.find('[')+2:item.find(']')-1]
            secondary = item[item.find('][')+3:item.find(']]')-1]
            if item.count("[") == 1:
                result['added primaries'].append(primary)
            else:
                result['added secondaries'].append((primary, secondary))
    if "values_changed" in diff.keys():
        for key, item in diff['values_changed'].items():
            primary = key[key.find('[')+2:key.find(']')-1]
            secondary = key[key.find('][')+3:key.find(']]')-1]
            result['changed values'].append((primary, secondary, item['new_value'], item['old_value']))
    return result


def print_messages(network_name: str, reference_name: str, diff, setting_name: str):
    if diff == {}:
        pp(f"[green]The network [bold]{network_name}[/bold] has the same {setting_name}s as the reference network [bold]{reference_name}[/bold].")
    else:
        parsed_diff = parse_diff(diff)
        for added_primary in parsed_diff['added primaries']:
            pp(f"[red]Network [bold]{network_name}[/bold] has an extra {setting_name}: {added_primary}.")
        for removed_primary in parsed_diff['removed primaries']:
            pp(f"[red]Network [bold]{network_name}[/bold] has a missing {setting_name}: {removed_primary}.")
        for added_secondary in parsed_diff['added secondaries']:
            key, setting = added_secondary
            pp(f"[yellow]Network [bold]{network_name}[/bold], setting {key} has an extra {setting_name}: [bold]{setting}[/bold].")
        for removed_secondary in parsed_diff['removed secondaries']:
            key, setting = removed_secondary
            pp(f"[yellow]Network [bold]{network_name}[/bold], setting {key} has a missing {setting_name}: [bold]{setting}[/bold].")
        for changed_value in parsed_diff['changed values']:
            key, setting, old_value, new_value = changed_value
            pp(f"[yellow]Network [bold]{network_name}[/bold], setting [bold]{key}[/bold] has changed the value of [bold]{setting}[/bold] from {old_value} to {new_value}.")   


async def main():
    async with meraki.aio.AsyncDashboardAPI(
        output_log=False, 
        suppress_logging=True, 
        maximum_concurrent_requests=5,
        wait_on_rate_limit=True,
        nginx_429_retry_wait_time=2,
        maximum_retries=100
            ) as aiomeraki:
        for network in networks:
            results[network['name']] = {}
        check_wireless_ssid_tasks = [check_wireless_ssid(aiomeraki, net, source_network) for net in networks if "wireless" in net['productTypes']]
        for task in asyncio.as_completed(check_wireless_ssid_tasks):
            await task
        check_wireless_rf_profiles_tasks = [check_wireless_rf_profiles(aiomeraki, net, source_network) for net in networks if "wireless" in net['productTypes']]
        for task in asyncio.as_completed(check_wireless_rf_profiles_tasks):
            await task
        check_wireless_wireless_settings_tasks = [check_wireless_settings(aiomeraki, net, source_network) for net in networks if "wireless" in net['productTypes']]
        for task in asyncio.as_completed(check_wireless_wireless_settings_tasks):
            await task
        pp("A bit of patience.. this is the slow part of the process (30 API calls per network)")
        check_wireless_wireless_l3_rules_tasks = [check_wireless_l3_rules(aiomeraki, net, source_network) for net in networks if "wireless" in net['productTypes']]
        for task in asyncio.as_completed(check_wireless_wireless_l3_rules_tasks):
            await task
        check_wireless_wireless_l7_rules_tasks = [check_wireless_l7_rules(aiomeraki, net, source_network) for net in networks if "wireless" in net['productTypes']]
        for task in asyncio.as_completed(check_wireless_wireless_l7_rules_tasks):
            await task
        check_wireless_wireless_shaping_rules_tasks = [check_wireless_shaping_rules(aiomeraki, net, source_network) for net in networks if "wireless" in net['productTypes']]
        for task in asyncio.as_completed(check_wireless_wireless_shaping_rules_tasks):
            await task
        '''check_switch_stp_tasks = [check_switch_stp(aiomeraki, net, source_network) for net in networks if "switch" in net['productTypes']]
        for task in asyncio.as_completed(check_switch_stp_tasks):
            await task'''
        check_switch_mtu_tasks = [check_switch_mtu(aiomeraki, net, source_network) for net in networks if "switch" in net['productTypes']]
        for task in asyncio.as_completed(check_switch_mtu_tasks):
            await task
        check_switch_acl_tasks = [check_switch_acl(aiomeraki, net, source_network) for net in networks if "switch" in net['productTypes']]
        for task in asyncio.as_completed(check_switch_acl_tasks):
            await task
        check_firmware_tasks = [check_firmware(aiomeraki, net, source_network) for net in networks]
        for task in asyncio.as_completed(check_firmware_tasks):
            await task
        
        #pp(results)

if __name__ == '__main__':
    # Initializing Meraki SDK
    dashboard = meraki.DashboardAPI(output_log=False, suppress_logging=True)
    pp("\n\nSelect source/template network:")
    networks, source_network = SelectNetwork()
    pp(20*"\n")
    results = {}

    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())
