from multiprocessing.pool import ThreadPool
from dumpings_requests import DumpRequests
import re
import random
from urllib.parse import urlsplit
from db import DB
from link_validator import LinkValidator
import tldextract
import requests
import json
from urllib.parse import urlparse
import lxml.html
from settings import get_base_setting
import logging
import time
from datetime import datetime


class Crawler:
    def __init__(self, start_links, thread_count, base_settings, db_connection, domains_collection_name,
                 domains_links_collection_name, proxy_list=(), inner_limit=3,
                 outer_limit=1, parsed_links={}, UPDATE_MODE=False, domains_settings={}, is_in_source_list=(),
                 dead_links=set(), eng_vers_mode=False, final_info=''):
        self.start_links = start_links
        self.inner_limit = inner_limit
        self.outer_limit = outer_limit
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/72.0.3626.81 Safari/537.36'}
        self.proxy_list = proxy_list
        self.is_in_source_list = is_in_source_list
        self.thread_count = thread_count
        self.dead_links = dead_links
        self.parsed_links = parsed_links
        self.UPDATE_MODE = UPDATE_MODE
        self.domains_settings = domains_settings
        self.link_validator = LinkValidator(technology_keywords=self.domains_settings['tech_keywords'],
                                            technology_full_keywords=self.domains_settings['tech_full_keywords'])
        self.base_settings = base_settings
        self.counters = {start_link['start_link']: {'counter': 0,
                                                    'last_time_called': 0,
                                                    'time_for_db': 0,
                                                    'time_for_request': 0,
                                                    'request_count': 0,
                                                    'time_read_dump': 0,
                                                    'dump_read_count': 0,
                                                    'dump_write_count': 0,
                                                    'dump_write_time': 0} for start_link in start_links}
        self.db_connection = db_connection
        self.domains_collection_name = domains_collection_name
        self.domains_links_collection_name = domains_links_collection_name
        self.eng_vers_mode = eng_vers_mode
        self.final_info = final_info

    # filter links by keywords
    def filter_links(self, links, start_link):
        logging.debug('start links filtering with {} links'.format(links.__len__()))
        new_links = []
        for link in links:
            try:
                # adding attributes to link test
                attributes_to_add = ['text', 'name', 'title']
                href = link.attrib['href']
                link_text = []
                link_text.append(link.text)
                for attribute in attributes_to_add:
                    try:
                        link_text.append(link.attrib[attribute])
                    except Exception:
                        pass
                link_text = ' '.join(link_text).strip()
            except Exception:
                continue
            remove_link = False
            if href == start_link:
                remove_link = True
            # checking ignore keywords in domain
            for keyword in self.domains_settings['domain_ignore_keywords']:
                if re.search(keyword, href, re.IGNORECASE):
                    remove_link = True
            # checking ignore keywords in the rest of href
            for keyword in self.domains_settings['ignore_keywords']:
                # if we found ignore word in link - remove it
                if re.search(keyword, href.replace(urlparse(href).netloc, ''), re.IGNORECASE):
                    remove_link = True
            # removing search links
            if href.endswith('/search/') or href.endswith('/search') or href.endswith('/search?'):
                # removing search bars
                remove_link = True
            if not remove_link:
                new_links.append((href, link_text))
        logging.debug('filtered {} of {} links'.format(len(new_links), len(links)))
        return new_links

    # merging and validating any type of links
    def valid_links(self, args):
        links = args['links']
        start_link = args['start_link']
        domain_link = args['domain_link']
        level_inner = args['level_inner']
        level_outer = args['level_outer']
        logging.debug('start links validation with {} links with {} inner level and {} outer level'.format(len(links),
                                                                                                           level_inner,
                                                                                                           level_outer))
        new_links = []
        for link in links:
            link_text = link[1]
            link = link[0].replace('\n', '')
            if link.startswith('/'):
                link = link[1:]
            link_netlock = urlsplit(link).netloc
            # if link to another site
            if link.replace('/', ''):
                if link_netlock:
                    if link_netlock != urlsplit(start_link).netloc:
                        # subdomens check
                        if tldextract.extract(link).domain == tldextract.extract(start_link).domain:
                            new_link = (link, link_text, 0)
                        else:
                            new_link = (link, link_text, 1)
                    else:
                        new_link = (link, link_text, 0)
                else:
                    # removing anchors and js links
                    if link.startswith('#') or link.endswith('()') or link.startswith('javascript('):
                        continue
                    else:
                        link = LinkValidator.merge_link(start_link, link)
                        new_link = (link, link_text, 0)

                if (level_outer == self.outer_limit and new_link[1] == 1) or (
                        level_inner == self.inner_limit and new_link[1] == 0):
                    continue
                # custom country check
                eng_abbreviations = ['en', 'eng', 'english']
                eng_patterns = [r'\.{abbreviation}\.', 'lang={abbreviation}', 'language={abbreviation}', r'\/{abbreviation}\/|\/{abbreviation}$']
                add_link = False
                if self.eng_vers_mode and start_link != domain_link and new_link[2] == 0:
                    for abbreviation in eng_abbreviations:
                        for pattern in eng_patterns:
                            if re.search(pattern.format(abbreviation=abbreviation), new_link[0], re.IGNORECASE):
                                add_link = True
                else:
                    add_link = True
                if add_link:
                    new_links.append(new_link)
        logging.debug('validated {} of {} links'.format(len(new_links), len(links)))
        return new_links

    def crawl(self, args):
        level_inner = args['level_inner']
        level_outer = args['level_outer']
        link = args['link']
        start_link = args['start_link']
        referal_url = args['referal_url']
        starter = args['starter']
        link_text = args['link_text']
        domain_link = args['domain_link']
        domains_filter = 'eng_version' if self.eng_vers_mode else '_id'
        if starter:
            self.counters[start_link]['counter'] = 0
            self.counters[start_link]['last_time_called'] = time.time()
        self.counters[start_link]['counter'] += 1
        if self.counters[start_link]['counter'] % 100 == 0:
            logging.info('{} links is parsed in {} sec on {} domain,'
                         ' time for db = {}, requests count = {}, time for requests = {},'
                         ' dump read count = {}, time_for_dump reading = {},'
                         ' dump write count = {}, time for dump writing = {}'.format(self.counters[start_link]['counter'],
                                                                                     time.time() - self.counters[start_link]['last_time_called'],
                                                                                     start_link,
                                                                                     self.counters[start_link]['time_for_db'],
                                                                                     self.counters[start_link]['request_count'],
                                                                                     self.counters[start_link]['time_for_request'],
                                                                                     self.counters[start_link]['dump_read_count'],
                                                                                     self.counters[start_link]['time_read_dump'],
                                                                                     self.counters[start_link]['dump_write_count'],
                                                                                     self.counters[start_link]['dump_write_time']))
            self.counters[start_link]['last_time_called'] = time.time()
            self.counters[start_link]['time_for_db'] = time.time()
            self.counters[start_link]['time_for_request'] = 0
            self.counters[start_link]['request_count'] = 0
            self.counters[start_link]['time_read_dump'] = 0
            self.counters[start_link]['dump_read_count'] = 0
            self.counters[start_link]['dump_write_count'] = 0
            self.counters[start_link]['dump_write_time'] = 0
        logging.debug('start to parse {} and UPDATE mode is set as {}'.format(link, str(self.UPDATE_MODE)))

        finished_inner_level = self.parsed_links.get(start_link, {}).get(link, {}).get('level_inner', 99999)
        finished_outer_level = self.parsed_links.get(start_link, {}).get(link, {}).get('level_outer', 99999)

        # if link href is empty or we already parse this link and got error response or we already parse this link
        # on more lower level, not parse it
        if not link or link in self.dead_links or (link == start_link and not starter) \
                or ((finished_inner_level < level_inner and finished_outer_level <= level_outer) or (
                finished_inner_level <= level_inner and finished_outer_level < level_outer)):
            logging.debug('link {} must be not parsed because of link is not valid to parse'.format(link))
            return
        # Update Mode check
        if self.UPDATE_MODE:
            site_alive_status = self.parsed_links.get(start_link, {}).get(link, {}).get('site_alive')
            finished_status = self.parsed_links.get(start_link, {}).get(link, {}).get(
                'finished-{}-{}'.format(self.inner_limit, self.outer_limit))
            # if links already checked and site_alive status is False, or we already finish this link, not parse it
            if site_alive_status is False or (
                    finished_status and (finished_inner_level == level_inner and finished_outer_level == level_outer)):
                if starter:
                    to_db_final = {'final.{}'.format(self.final_info): True}
                    to_db_final[domains_filter] = start_link
                    t1 = time.time()
                    self.db_connection.update_items_in_db(self.domains_collection_name,
                                                          [to_db_final],
                                                          filtr=[domains_filter], upsert=False)
                    self.counters[start_link]['time_for_db'] += time.time() - t1
                if site_alive_status is False:
                    logging.debug('link {} already parsed and site alive status set as False')
                else:
                    logging.debug('link {} is finished and UPDATE mode set as {}'.format(link, str(self.UPDATE_MODE)))
                return
        # getting 3 random proxy
        try:
            proxies = [{'https': random.choice(self.proxy_list)} for _ in range(3)]
        except IndexError:
            proxies = []
        logging.debug('{} proxies is taken'.format(proxies))
        download_directory = self.base_settings['download_directory'] + '/crawler/{}'.format(
            start_link.replace('/', '_'))
        # getting response or dump text
        d = DumpRequests('GET', link,
                         download_directory,
                         timeout=20,
                         proxies=proxies,
                         headers=self.headers)

        status, response_text, dump_read_time, dump_write_time, request_time = d.make_request()
        if dump_read_time:
            self.counters[start_link]['time_read_dump'] += dump_read_time
            self.counters[start_link]['dump_read_count'] += 1
        else:
            self.counters[start_link]['time_for_request'] += request_time
            self.counters[start_link]['request_count'] += 1
            if dump_write_time:
                self.counters[start_link]['dump_write_time'] += dump_write_time
                self.counters[start_link]['dump_write_count'] += 1

        # getting keywords in link and their rank
        keywords_ranks = self.link_validator.get_keywords_rank(link, link_text)
        to_db_info = {}
        # if status, setting site_alive as True
        if status:
            to_db_info['site_alive'] = True
        else:
            to_db_info['site_alive'] = False
            self.dead_links.update(link)
        to_db_info.update(keywords_ranks)
        to_db_info['referal_url'] = referal_url
        to_db_info['is_in_source'] = True if urlparse(start_link).netloc in self.is_in_source_list else False

        to_db_info.update({'keywords_status': True if len(keywords_ranks['keywords']) > 0 else False})
        to_db_info.update({'link_text_keywords_status': True if len(keywords_ranks['keywords_in_text']) > 0 else False})
        to_db_info.update({'full_keywords_keywords_status': True if len(keywords_ranks['full_keywords']) > 0 else False})
        to_db_info.update({'full_link_text_keywords_status': True if len(keywords_ranks['full_keywords_in_text']) > 0 else False})
        to_db_info.update({'level_inner': level_inner})
        to_db_info.update({'level_outer': level_outer})
        # db upload
        technologies = {}
        for k, v in to_db_info.items():
            technologies['link_info.{}'.format(k)] = v
        technologies['domain'] = start_link
        technologies['link_info.link'] = link
        del to_db_info

        link_finish = {}
        link_finish['link_info.finished-{}-{}'.format(self.inner_limit, self.outer_limit)] = True
        link_finish['domain'] = start_link
        link_finish['link_info.link'] = link
        # parsing last inner level only if we found keywords
        if keywords_ranks['keywords'].__len__() == 0 and level_inner == self.inner_limit - 1:
            logging.debug('no keywords and pre last inner level for {} link'.format(link))
            t1 = time.time()
            self.db_connection.update_items_in_db(self.domains_links_collection_name,
                                                  [link_finish],
                                                  filtr=['domain', 'link_info.link'])
            self.counters[start_link]['time_for_db'] += time.time() - t1
            del link_finish
            return
        del keywords_ranks
        # if level == inner limit, we doesnt make a requests
        if status and (level_inner < self.inner_limit) and (level_outer < self.outer_limit):
            logging.debug('starting to find child links on {} link'.format(link))
            # getting all "a" tags
            try:
                tree = lxml.html.fromstring(response_text)
                all_links_raw = tree.xpath('//a')
                del tree
            except ValueError:
                all_links_raw = []
            # filtering links by keywords
            all_links = self.valid_links({'links': self.filter_links(all_links_raw, start_link),
                                          'start_link': start_link,
                                          'domain_link': domain_link,
                                          'level_outer': level_outer,
                                          'level_inner': level_inner})

            del all_links_raw
            del response_text
            args = [{'level_inner': level_inner + 1,
                     'level_outer': level_outer + new_link[2],
                     'link': new_link[0],
                     'link_text': new_link[1],
                     'referal_url': link,
                     'start_link': start_link,
                     'domain_link':domain_link,
                     'starter': False} for new_link in all_links if new_link]
            del all_links
            technologies['link_info.child_links'] = args.__len__()
            logging.debug('founded {} child links on {}'.format(args.__len__(), link))
            if self.UPDATE_MODE and self.parsed_links.get(start_link, {}).get(link):
                pass
            else:
                t1 = time.time()
                self.db_connection.update_items_in_db(self.domains_links_collection_name,
                                                      [technologies],
                                                      filtr=['domain', 'link_info.link'])
                self.counters[start_link]['time_for_db'] += time.time() - t1
            self.parsed_links.setdefault(start_link, {})[link] = {'site_alive': status,
                                                                  'level_inner': level_inner,
                                                                  'level_outer': level_outer}
            del technologies
            for arg in args:
                self.crawl(arg)
            del args
        else:
            if self.UPDATE_MODE and self.parsed_links.get(start_link, {}).get(link):
                pass
            else:
                t1 = time.time()
                self.db_connection.update_items_in_db(self.domains_links_collection_name,
                                                      [technologies],
                                                      filtr=['domain', 'link_info.link'])
                self.counters[start_link]['time_for_db'] += time.time() - t1
            del technologies
            self.parsed_links.setdefault(start_link, {})[link] = {'site_alive': status,
                                                                  'level_inner': level_inner,
                                                                  'level_outer': level_outer}
        t1 = time.time()
        self.db_connection.update_items_in_db(self.domains_links_collection_name, [link_finish],
                                              filtr=['domain', 'link_info.link'])
        self.counters[start_link]['time_for_db'] += time.time() - t1
        logging.debug('link {} is finished'.format(link))
        del link_finish
        # if domain link is finished, creating final sign on domain item
        if starter:
            logging.info('domain {} is finished'.format(link))
            to_db_final = {'final.{}'.format(self.final_info): True}
            to_db_final[domains_filter] = start_link
            t1 = time.time()
            self.db_connection.update_items_in_db(self.domains_collection_name,
                                                  [to_db_final],
                                                  filtr=[domains_filter], upsert=False)
            self.counters[start_link]['time_for_db'] += time.time() - t1
            del to_db_final
            return

    def run(self):
        logging.info('creating pool')
        pool = ThreadPool(self.thread_count)
        pool.map(self.crawl, [{'link': link['start_link'],
                               'link_text': '',
                               'start_link': link['start_link'],
                               'level_inner': 1,
                               'level_outer': 0,
                               'starter': True,
                               'referal_url': link['start_link'],
                               'domain_link': link['domain_link'],
                               'counter': 0} for link in self.start_links])


# function to get domains by abbreviation, full country name and rank
def get_bd_start_links(db_connection, domains_collection_name, domain_links_collection_name,
                       abbreviation='', full_country_name='', top_ranks=-1, domain_limit=0, eng_vers_mode=False):
    logging.info('starting to get domains and parsed links from db')
    # print("domains_limit 1: {}".format(domain_limit))
    if eng_vers_mode:
        items = db_connection.get_items_from_db(domains_collection_name,
                                                {'$or': [
                                                    {'meta.country': {'$regex': full_country_name, '$options': 'i'}},
                                                    {'meta.country.abbreviation': {'$regex': abbreviation,
                                                                                   '$options': 'i'}}],
                                                    'eng_version': {'$ne': None}}, limit=domain_limit)
    else:
        items = db_connection.get_items_from_db(domains_collection_name,
                                                {'$or': [
                                                    {'meta.country': {'$regex': full_country_name, '$options': 'i'}},
                                                    {'meta.country.abbreviation': {'$regex': abbreviation,
                                                                                   '$options': 'i'}}]},
                                                limit=domain_limit)

    start_links = []
    parsed_items = {}
    dead_links = []
    # getting sources by name
    for item in items:
        if item.get('meta'):
            country_item = item['meta'].get('country')
            if country_item and (full_country_name or abbreviation):
                valid_item = None
                # searching by full country name
                if type(country_item) == str:
                    if re.search(full_country_name, country_item, re.IGNORECASE):
                        valid_item = item
                # searching by abbreviation
                elif type(country_item) == dict:
                    if re.search(abbreviation, country_item.get('abbreviation'), re.IGNORECASE):
                        valid_item = item
                if valid_item:
                    item_rank = None
                    # filter by rank
                    if item['meta'].get('rank'):
                        item_rank = item['meta']['rank']
                    elif item['meta'].get('country_rank'):
                        item_rank = item['meta'].get('country_rank')
                    get_items = False
                    if item_rank and top_ranks >= 0:
                        if top_ranks >= item_rank:
                            get_items = True
                    else:
                        get_items = True
                    if get_items:
                        link_to_add = item.get('eng_version') if eng_vers_mode else item['_id']
                        if not link_to_add:
                            continue
                        if 'http' in link_to_add:
                            start_links.append({'start_link': link_to_add, 'domain_link': item['_id']})
    all_domains_links = db_connection.get_items_from_db(domain_links_collection_name,
                                                        {'domain': {'$in': [link['start_link'] for link in start_links]}})
    for doc in all_domains_links:
        link = doc['link_info']['link']
        copy_doc_info = doc['link_info'].copy()
        copy_doc_info.pop('link')
        info = copy_doc_info
        parsed_items.setdefault(doc['domain'], {}).setdefault(link, info)
        if info.get('site_alive') is False:
            dead_links.append(link)
    return start_links, parsed_items, set(dead_links)


def get_proxies(proxies_list=[], proxies_link=''):
    if not proxies_list:
        proxies_link = proxies_link if proxies_link else 'http://64.140.158.34:5000'
        proxy_list = json.loads(requests.get(proxies_link).text)
    else:
        proxy_list = proxies_list
    return proxy_list


def get_domains_settings(db_connect, collection_name):
    settings = list(db_connect.get_items_from_db(collection_name, {}))[0]
    tech_keywords = settings.get('tech_keywords', {})
    for k, v in tech_keywords.items():
        if v == '':
            tech_keywords[k] = 1
    tech_full_keywords = settings.get('tech_full_keywords', {})
    for k, v in tech_full_keywords.items():
        if v == '':
            tech_full_keywords[k] = 1

    return {'tech_keywords': tech_keywords,
            'tech_full_keywords': tech_full_keywords,
            'ignore_keywords': settings.get('ignore_keywords', []),
            'contact_keywords': settings.get('contact_keywords', []),
            'domain_ignore_keywords': settings.get('domain_ignore_keywords', [])}


def run(base_settings):
    # getting start links and already parser items
    start_links, parsed_links, dead_links = get_bd_start_links(connect_to_db, user_settings['domains_collection_name'],
                                                               user_settings['domains_links_collection_name'],
                                                               user_settings.get('abbreviation', ''),
                                                               user_settings.get('full_country_name', ''),
                                                               top_ranks=user_settings.get('rank_limit', -1),
                                                               domain_limit=int(user_settings.get('domain_limit', 0)),
                                                               eng_vers_mode=user_settings['modes_for_crawler'].get('Eng_vers_mode', False))
    logging.info('started with start links {}'.format(str([link['start_link'] for link in start_links])))
    logging.info('selecting from db is finished')
    raw_sources = connect_to_db.get_items_from_db(user_settings['sources_collection_name'], {}, {'_id': 0, 'domain': 1})
    is_in_source_list = [urlparse(item['domain']).netloc for item in raw_sources]
    # removing bad source
    damaged_sources = ['http://www.napier.ac.uk']
    valid_start_links = []
    for damaged_source in damaged_sources:
        for start_link in start_links:
            if start_link['start_link'] != damaged_source:
                valid_start_links.append(start_link)
            else:
                logging.info('{} domain removed from start link'.format(damaged_source))
    logging.info('founded {} start links, {} dead links'.format(len(valid_start_links), len(dead_links)))
    # getting proxies
    proxy_list = get_proxies(proxies_list=user_settings.get('proxies_list', []),
                             proxies_link=user_settings.get('proxies_link', ''))
    logging.info('founded {} proxies'.format(len(proxy_list)))
    random.shuffle(valid_start_links)
    thread_count = user_settings.get('thread_count')
    if not thread_count:
        thread_count = valid_start_links.__len__()
    logging.info('crawler started with {} domains in {} threads'
                 ' with {} inner limit and {} outer_limit. UPDATE mode set as "{}".'
                 ' Eng versing mode set as "{}"'.format(len(valid_start_links),
                                                        thread_count,
                                                        user_settings['inner_limit'],
                                                        user_settings['outer_limit'],
                                                        str(user_settings['modes_for_crawler']['Update_mode']),
                                                        str(user_settings['modes_for_crawler']['Eng_vers_mode'])))
    final_info = '{}-{}-{}-{}'.format(datetime.now().strftime('%Y-%m-%d'),
                                      user_settings.get('abbreviation', ''),
                                      user_settings['inner_limit'],
                                      user_settings['outer_limit'])
    logging.info(final_info)
    instance = Crawler(start_links=valid_start_links,
                       parsed_links=parsed_links,
                       dead_links=dead_links,
                       thread_count=thread_count,
                       db_connection=connect_to_db,
                       domains_collection_name=user_settings['domains_collection_name'],
                       domains_links_collection_name=user_settings['domains_links_collection_name'],
                       is_in_source_list=is_in_source_list,
                       domains_settings=domains_settings,
                       proxy_list=proxy_list,
                       inner_limit=user_settings['inner_limit'],
                       outer_limit=user_settings['outer_limit'],
                       UPDATE_MODE=user_settings['modes_for_crawler']['Update_mode'],
                       base_settings=base_settings,
                       eng_vers_mode=user_settings['modes_for_crawler'].get('Eng_vers_mode', False),
                       final_info=final_info)

    instance.run()


if __name__ == '__main__':
    base_settings = get_base_setting()
    domains_user_settings_collection_name = base_settings['domains_user_settings_collection_name']
    db_uri = base_settings['db_uri']
    db_name = base_settings['db_name']
    connect_to_db = DB(db_url=db_uri, db_name=db_name)
    user_settings = list(connect_to_db.get_items_from_db(domains_user_settings_collection_name, {}).limit(1))[0]

    debug_level = getattr(logging, user_settings['debug_level'].upper())
    logging.basicConfig(format=u'%(filename)s[LINE:%(lineno)d]# %(levelname)-8s [%(asctime)s]  %(message)s',
                        level=debug_level)

    # getting domains settings
    domains_settings = get_domains_settings(connect_to_db, user_settings['domains_settings_collection_name'])
    logging.info('user setting is received')
    logging.info(
        'connected to {} database with {} mongodb_uri'.format(base_settings['db_name'], base_settings['db_uri']))
    # run crawler
    run(base_settings)
