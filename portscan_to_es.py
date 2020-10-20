#coding=utf-8
import re
import time
import requests
from elasticsearch import Elasticsearch

def to_es(today_date,es,ip,port='',port_state='normal',host_state='normal',state_change='',protocol='',service='',reason='',state=''):
    es.indices.create(index='portscan', ignore=400)
    # date = time.strftime("%Y-%m-%d")
    es.index(index="portscan", doc_type="portscan", body={"ip": ip, "port":port ,"port_state": port_state,"host_state":host_state,"state_change":state_change,"protocol":protocol,"service":service,"reason":reason,"state":state,"date":today_date})

def to_portscan_num(today_date):
    # date = time.strftime("%Y-%m-%d")
    ftoday = open('./data/'+today_date+'.report')
    allhtml_today = ftoday.read()
    begin_time_str = re.findall(r'<taskbegin task="Ping Scan" time="(.*?)"/>',allhtml_today,re.S)
    begin_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(int(begin_time_str[0])))#扫描时间
    scan_time_str = re.findall(r'\) scanned in (.*?) seconds"',allhtml_today)
    scan_time = scan_time_str[0]
    total_host_today = re.findall(r'extrainfo="(.*?) total hosts"/>',allhtml_today)[0]
    es = Elasticsearch('es_ip',http_auth=('name', 'passwd'),port=9200)

    alive_htmls_today = re.findall(r'<host starttime=(.*?)</host>',allhtml_today,re.S)
    port_open_num = allhtml_today.count('<state state="open"') 
    data = {
        "size":0,
        "query": {  
            "bool": {  
                "must":{ "term": {"port_state": "close"}}
              }  
        }  
    }
    port_close_num = es.search(index='portscan',doc_type='portscan',body=data)['hits']['total']

    data = {
        "size":0,
        "query": {  
            "bool": {  
                "must":{ "term": {"host_state": "down"}}
              }  
        }  
    }
    host_close_num = es.search(index='portscan',doc_type='portscan',body=data)['hits']['total']

    host_open_num = len(alive_htmls_today)
    es.indices.create(index='portscan_num', ignore=400)
    es.index(index="portscan_num", doc_type="portscan_num", body={"port_open_num": port_open_num, "port_close_num":port_close_num,"host_open_num":host_open_num,"host_close_num":host_close_num, "date":today_date,"begin_time":begin_time,"scan_time":scan_time,"total_host":total_host_today})


def to_portscan(today_date,fyesterday):
    es = Elasticsearch('es_ip',http_auth=('name', 'passwd'),port=9200)
    requests.delete("http://name:passwd@es_ip:es_port/portscan") 
    allhtml_yesterday = fyesterday.read()
    total_htmls_yesterday = re.findall(r'<host(.*?)</host>',allhtml_yesterday,re.S)
    total_yesterday =  len(total_htmls_yesterday)
    down_htmls_yesterday = re.findall(r'<host>(.*?)</host>',allhtml_yesterday,re.S)
    alive_htmls_yesterday = re.findall(r'<host starttime=(.*?)</host>',allhtml_yesterday,re.S)
    down_num_yesterday =  len(down_htmls_yesterday)
    alive_num_yesterday =  len(alive_htmls_yesterday)
    down_ip_yesterday,alive_ip_yesterday,protocol_yesterday,port_yesterday,state_yesterday,reason_yesterday,service_yesterday = [1]*down_num_yesterday,[1]*alive_num_yesterday,[],[1]*alive_num_yesterday,[1]*alive_num_yesterday,[1]*alive_num_yesterday,[1]*alive_num_yesterday
    for i in range(down_num_yesterday):
        down_ip_yesterday[i] = re.findall('<address addr="(.*)" addrtype=',down_htmls_yesterday[i])[0]#昨天不在线主机 数组
    for i in range(alive_num_yesterday):
        alive_ip_yesterday[i] = re.findall('<address addr="(.*)" addrtype=',alive_htmls_yesterday[i])[0]#昨天在线主机 数组
    
    ftoday = open('./data/'+today_date+'.report')
    allhtml_today = ftoday.read()
    down_htmls_today = re.findall(r'<host>(.*?)</host>',allhtml_today,re.S)

    alive_htmls_today = re.findall(r'<host starttime=(.*?)</host>',allhtml_today,re.S)
    
#插入所有数据
    for alive_html_today in alive_htmls_today:
        host_state,port_state,state_now = 'normal','normal',2
        alive_ip_today = re.findall('<address addr="(.*)" addrtype=',alive_html_today)[0]#今天在线主机 变量
        if(alive_ip_today not in down_ip_yesterday and alive_ip_today not in alive_ip_yesterday):
            host_state = 'add'#今天在线，昨天未扫描，新增主机 add
            state_now = '1'
            port_state = 'open'
        if alive_ip_today in down_ip_yesterday:
            host_state = 'add'#今天在线，昨天不在线，新增主机 add
            state_now = '1'
            port_state = 'open'
        #插入所有数据
        html = alive_html_today.split('<port ')
        for n in range(1,len(html)):
            state_today = re.findall('<state state="(.*?)" reason',html[n])[0]
            if state_today=='open':  
                protocol_today = re.findall('protocol="(.*?)" portid',html[n])[0]
                port_today = re.findall('portid="(.*?)"><state',html[n])[0]
                reason_today = re.findall('reason="(.*?)" reason_ttl',html[n])[0]
                if '<service name=' in html[n]:
                    service_today = re.findall('<service name="(.*?)" method="',html[n])[0]
                else:
                    service_today = ''
                to_es(today_date,es,alive_ip_today,port_today,port_state,host_state,state_now,protocol_today,service_today,reason_today,state_today)
#更改变动数据
    for alive_html_today in alive_htmls_today:
        alive_ip_today = re.findall('<address addr="(.*)" addrtype=',alive_html_today)[0]#今天在线主机 变量

        #今天在线主机，详细信息 变量
        for i in range(alive_num_yesterday):
            if '<address addr="'+alive_ip_today+'"' in alive_htmls_yesterday[i]:
                in_port_yesterday = re.findall('<port protocol=.*portid="(.*)"><state state="',alive_htmls_yesterday[i])
                for port_yesterday1 in in_port_yesterday:
                    port_today1 = re.findall('<port protocol=.*portid="(.*)"><state state="',alive_html_today)
                    port_state_yesterday = re.findall('<port protocol=".*" portid="'+port_yesterday1+'"><state state="(.*?)"',alive_htmls_yesterday[i])[0]
                    if (port_yesterday1 not in port_today1 and port_state_yesterday=='open'):
                        #今天没扫，昨天扫描，关闭   !!!!!!
                        to_es(today_date,es,alive_ip_today,port_yesterday1,'close','normal',1)

            port_state = 'normal'
            try:
                if '<address addr="'+alive_ip_today+'"' in alive_htmls_yesterday[i]:
                    in_port_today = re.findall(r'<port protocol=.*portid="(.*)"><state state="',alive_html_today,re.M)
                    in_state_today = re.findall(r'"><state state="(.*)" reason="',alive_html_today,re.M)
                    for m in range(len(in_port_today)):
                        port_yesterday = re.findall('<port protocol=.*portid="(.*)"><state state="',alive_htmls_yesterday[i])
                        if (in_port_today[m] not in port_yesterday and in_state_today[m] == 'open'):
                            #今天扫描，昨天没扫，新增 !!!!
                            data = {
                            "query": {  
                            "bool": {  
                            "must": [ 
                              { "term": {"ip": alive_ip_today}},
                              { "term": {"port": in_port_today[m]}}
                                ]
                              }  
                              }  
                            }
                            res = es.search(index='portscan',doc_type='portscan',body=data)
                            for n in res['hits']['hits']:
                                es.update(index="portscan", doc_type="portscan", id=n['_id'], body={"doc" : {"port_state" : "open","state_change":1}})
                            # to_es(es,alive_ip_today,in_port_today[m],'open','normal',1)
                        if (alive_ip_today  and '"'+in_port_today[m]+'"') in alive_htmls_yesterday[i]:
                            state_yesterday = re.findall(r'<address addr="'+alive_ip_today+'".*portid="'+in_port_today[m]+'"><state state="(.*?)" reason="',alive_htmls_yesterday[i],re.S)[0]
                        if (in_state_today[m] == 'open' and state_yesterday!='open'):
                            #都扫描  今天开放，昨天关闭，端口开放  open
                            data = {
                            "query": {  
                            "bool": {  
                            "must": [ 
                              { "term": {"ip": alive_ip_today}},
                              { "term": {"port": in_port_today[m]}}
                                ]
                              }  
                              }  
                            }
                            res = es.search(index='portscan',doc_type='portscan',body=data)
                            for n in res['hits']['hits']:
                                # print 11111
                                es.update(index="portscan", doc_type="portscan", id=n['_id'], body={"doc" : {"port_state" : "open","state_change":1}})

                        
                        if (in_state_today[m] != 'open' and state_yesterday=='open'):
                            port_state = 'close'#都扫描  今天关闭，昨天开放，关闭端口  close
                            data = {
                            "query": {  
                            "bool": {  
                            "must": [ 
                              { "term": {"ip": alive_ip_today}},
                              { "term": {"port": in_port_today[m]}}
                                ]
                              }  
                              }  
                            }
                            res = es.search(index='portscan',doc_type='portscan',body=data)
                            for n in res['hits']['hits']:
                                es.update(index="portscan", doc_type="portscan", id=n['_id'], body={"doc" : {"port_state" : "close","state_change":1}})
            except Exception as e:
                print e
                continue
    for down_html_today in down_htmls_today:
        alldown_ip_today = re.findall('<address addr="(.*)" addrtype=',down_html_today)[0]#今天不在线主机 变量
        #今天不在线，昨天在线，下线
        if alldown_ip_today in alive_ip_yesterday:
            for i in range(alive_num_yesterday):
                if '<address addr="'+alldown_ip_today+'"' in alive_htmls_yesterday[i]:
                    in_port_yesterday = re.findall('<port protocol=.*portid="(.*)"><state state="',alive_htmls_yesterday[i])
                    for port in in_port_yesterday:
                        port_state_yesterday,reason = re.findall('<port protocol=".*" portid="'+port+'"><state state="(.*?)" reason="(.*?)"',alive_htmls_yesterday[i])[0]
                        if port_state_yesterday == "open":
                            host_state = 'down'
                            to_es(today_date,es,alldown_ip_today,port,'close',host_state,1,'','',reason)#状态更改
        else:
            host_state = 'outline'
            to_es(today_date,es,alldown_ip_today,'','',host_state,2)#状态未更改

    

def to_port_charts(len):
    #将数据分割并存入索引portcharts,方便图表展示
    #ip前50数组
    data = {
    "size": 0,
    "aggs": {
    "uniq_streets": {
      "terms":{
        "field" :"ip.keyword",
        "size" : len
    }
    }
    },
    "query":{
        "bool":{
            "must_not":{
                "term":{"host_state.keyword":"outline"}
            }
        }
    }  
    }
    es = Elasticsearch('es_ip',http_auth=('name', 'passwd'),port=9200)
    ips_search = es.search(index='portscan',doc_type='portscan',body=data)
    ips = []
    for n in ips_search['aggregations']['uniq_streets']['buckets']:
        ips.append(str(n['key']))

    data = {
    "size": 0,
    "aggs": {
    "uniq_streets": {
      "terms":{
        "field" :"port.keyword",
        "size" : len
    }
    }
    },
    "query":{
        "bool":{
            "must_not":{
                "term":{"host_state.keyword":"outline"}
            }
        }
    } 
    }
    port_search = es.search(index='portscan',doc_type='portscan',body=data)
    dicts = [1]*len
    for i in range(len):#遍历每个ip
        ports_state_one = []
        dict = {}
        dict['data'] = [1]*len
        dict['name'] = ips[i]
        dict['type'] = "bar"
        dict['stack'] = '总量'.decode('utf-8')
        ports = []
        for port_value in port_search['aggregations']['uniq_streets']['buckets']:#遍历每个port，需要一个ip对应一个端口，找出端口状态
            ports.append(port_value['key'])#所有端口数组
            data = {
            "query": {
                "bool": {
                  "must":[
                    {"term":{"ip.keyword" :ips[i]}},
                    {"term":{"port.keyword" :port_value['key']}}
                  ]
                }
              }
            }
            ip_port_search = es.search(index='portscan',doc_type='portscan',body=data)
            if ip_port_search['hits']['hits']:
                for port in ip_port_search:  
                    if (port!='close'):
                        ports_state_one = 1#单个ip端口状态为1
            else:
                ports_state_one = 0#单个ip端口状态为0  
            dict['data'][i] = ports_state_one
        dicts[i] = dict


    ##端口对应多ip数组
    dicts1 = [1]*len
    for i in range(len):#遍历每个port
        ips_state_one = []
        dict1 = {}
        dict1['data'] = [1]*len
        dict1['name'] = ports[i]
        dict1['type'] = "bar"
        dict1['stack'] = '总量'.decode('utf-8')
        ips = []
        m = 0
        for ips_value in ips_search['aggregations']['uniq_streets']['buckets']:#遍历每个port，需要一个ip对应一个端口，找出端口状态
            ips.append(str(ips_value['key']))#所有ip数组
            data = {
            "query": {
                "bool": {
                  "must":[
                    {"term":{"port.keyword" :ports[i]}},
                    {"term":{"ip.keyword" :ips_value['key']}}
                  ]
                }
              }
            }
            port_ip_search = es.search(index='portscan',doc_type='portscan',body=data)
            if port_ip_search['hits']['hits']:
                if (port_ip_search['hits']['hits'][0]['_source']['port_state']!='close'):
                    ips_state_one=1#单个port主机状态为1
            else:
                ips_state_one=0#单个port主机状态为0  
            dict1['data'][m] = ips_state_one
            m = m+1
        dicts1[i] = dict1
    #存入es
    requests.delete("http://name:passwd@es_ip:es_port/portscan_charts") 
    es.indices.create(index='portscan_charts', ignore=400)
    date = time.strftime("%Y-%m-%d")
    es.index(index="portscan_charts", doc_type="portscan_charts", body={"ips": ips, "ports":ports ,"dicts1": dicts1,"dicts":dicts})

today_date = time.strftime("%Y-%m-%d")
# today_date = '2018-09-20'
fyesterday = open('./data/'+time.strftime('%Y-%m-%d',time.localtime(time.time()-86400))+'.report')
# fyesterday = open('./data/2018-09-19.report')
to_portscan(today_date,fyesterday)
to_port_charts(20)
to_portscan_num(today_date)