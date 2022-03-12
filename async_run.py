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
    try:
        reference_ssids = await aiomeraki.wireless.getNetworkWirelessSsids(reference_network['id'])    
    except Exception as e:
        pp(f'[bold magenta]Some other ERROR: {e}')
    try:
        network_ssids = await aiomeraki.wireless.getNetworkWirelessSsids(network['id'])
    except Exception as e:
        pp(f'[bold magenta]Some other ERROR: {e}')
    diff = DeepDiff(reference_ssids, network_ssids, group_by='name', ignore_order=True)
    print_messages(network['name'], reference_network['name'], diff, "SSID")
    results[network['name']]['ssids'] = diff


async def check_wireless_rf_profiles(aiomeraki: meraki.aio.AsyncDashboardAPI, network: dict, reference_network: dict):
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


async def check_switch_stp(aiomeraki: meraki.aio.AsyncDashboardAPI, network: dict, reference_network: dict):
    try:
        reference_settings = await aiomeraki.wireless.getNetworkSwitchStp(reference_network['id'])    
    except Exception as e:
        pp(f'[bold magenta]Some other ERROR: {e}')
    try:
        network_settings = await aiomeraki.wireless.getNetworkSwitchStp(network['id'])
    except Exception as e:
        pp(f'[bold magenta]Some other ERROR: {e}')
    diff = DeepDiff(reference_settings, network_settings, ignore_order=True)
    print_messages(network['name'], reference_network['name'], diff, "STP setting")
    results[network['name']]['stp_settings'] = diff


async def check_switch_mtu(aiomeraki: meraki.aio.AsyncDashboardAPI, network: dict, reference_network: dict):
    try:
        reference_settings = await aiomeraki.wireless.getNetworkSwitchMtu(reference_network['id'])    
    except Exception as e:
        pp(f'[bold magenta]Some other ERROR: {e}')
    try:
        network_settings = await aiomeraki.wireless.getNetworkSwitchMtu(network['id'])
    except Exception as e:
        pp(f'[bold magenta]Some other ERROR: {e}')
    diff = DeepDiff(reference_settings, network_settings, ignore_order=True)
    print_messages(network['name'], reference_network['name'], diff, "MTU setting")
    results[network['name']]['mtu_settings'] = diff


async def check_switch_acl(aiomeraki: meraki.aio.AsyncDashboardAPI, network: dict, reference_network: dict):
    try:
        reference_settings = await aiomeraki.wireless.getNetworkSwitchAccessControlLists(reference_network['id'])    
    except Exception as e:
        pp(f'[bold magenta]Some other ERROR: {e}')
    try:
        network_settings = await aiomeraki.wireless.getNetworkSwitchAccessControlLists(network['id'])
    except Exception as e:
        pp(f'[bold magenta]Some other ERROR: {e}')
    diff = DeepDiff(reference_settings, network_settings, ignore_order=True)
    print_messages(network['name'], reference_network['name'], diff, "ACL")
    results[network['name']]['acls'] = diff


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
        pp(f"[green]The network {network_name} has the same {setting_name}s as the reference network {reference_name}.")
    else:
        parsed_diff = parse_diff(diff)
        for added_primary in parsed_diff['added primaries']:
            pp(f"[red]Network {network_name} has an extra {setting_name}: {added_primary}.")
        for removed_primary in parsed_diff['removed primaries']:
            pp(f"[red]Network {network_name} has a missing {setting_name}: {removed_primary}.")
        for added_secondary in parsed_diff['added secondaries']:
            key, setting = added_secondary
            pp(f"[yellow]Network {network_name}, setting {key} has an extra {setting_name}: {setting}.")
        for removed_secondary in parsed_diff['removed secondaries']:
            key, setting = removed_secondary
            pp(f"[yellow]Network {network_name}, setting {key} has a missing {setting_name}: {setting}.")
        for changed_value in parsed_diff['changed values']:
            key, setting, old_value, new_value = changed_value
            pp(f"[yellow]Network {network_name}, setting {key} has changed the value of {setting} from {old_value} to {new_value}.")   


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
        check_switch_stp_tasks = [check_switch_stp(aiomeraki, net, source_network) for net in networks if "switch" in net['productTypes']]
        for task in asyncio.as_completed(check_switch_stp_tasks):
            await task
            

        pp(results)

if __name__ == '__main__':
    # Initializing Meraki SDK
    dashboard = meraki.DashboardAPI(output_log=False, suppress_logging=True)
    pp("\n\nSelect source/template network:")
    networks, source_network = SelectNetwork()
    results = {}

    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())
