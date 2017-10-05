import json
import pyasn

from ResultFetcher import ResultFetcherProxy
from DataAdapter import ResultDataAdapter
from AutocorrelationUtility import AutocorrelationUtility
from PeriodicityCharacterizer import PeriodicityCharacterizer
from collections import OrderedDict


def levenshtein(s1, s2):
    if len(s1) < len(s2):
        return levenshtein(s2, s1)

    # len(s1) >= len(s2)
    if len(s2) == 0:
        return len(s1)

    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1 # j+1 instead of j since previous_row and current_row are one character longer
            deletions = current_row[j] + 1       # than s2
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    
    return previous_row[-1]


def extractMetadataRecord(line):
	'''extract metadata'''
	prbIdSource = line["prb_id"]
	idMeas = line["msm_id"]
	timestamp = int(line["timestamp"])
	result=line["result"]
	return prbIdSource,idMeas,timestamp,result


def extractTracerouteString(result):
	'''transform the traceroute sequence into a string'''
	tracerouteString=""
	rttString=""
	for counter in range(0,len(result)):
			try:
				tracerouteString+=result[counter]["result"][0]["from"]+"-"
				rttString+=result[counter]["result"][0]["rtt"]+"-"
			except:
				tracerouteString+="*-"
	return tracerouteString[:-1],rttString[:-1]


def getPairToTime2traceroute(pathToFile):
	'''Given the fragmented json as input it returns a two levels map\
	containing the id of probe-measuremenent as key and value another map
	in the form of timestamp traceroute'''

	with open(pathToFile) as f:

		pairToTime2traceroute=dict()

		for line in f:
			lineParsed=json.loads(line)

			prbIdSource,idMeas,timestamp,result=extractMetadataRecord(lineParsed)
			pairId=str(prbIdSource)+"-"+str(idMeas)
			
			if pairId not in pairToTime2traceroute.keys():
				pairToTime2traceroute[pairId]=dict()

			tracerouteString,rttString=extractTracerouteString(result)
			pairToTime2traceroute[pairId][timestamp]=[tracerouteString,rttString]

	return pairToTime2traceroute


def getTracerouteToIDs(pair,pairToTime2traceroute):
	'''It returns two maps in the form of traceroute to id and vice versa'''
	tracerouteToTimestamp=dict()
	tracerouteToId=dict()
	idToTraceroute=dict()

	idCounter=100
	timestampToTracerouteAndRTT=pairToTime2traceroute[pair]

	for timestamp in sorted(timestampToTracerouteAndRTT.keys()):
		traceroute=timestampToTracerouteAndRTT[timestamp][0]

		if traceroute not in tracerouteToId:
			tracerouteToId[traceroute]=idCounter
			idToTraceroute[idCounter]=traceroute

			idCounter+=100
	return tracerouteToId,idToTraceroute


def getTracerouteIDsSequence(pair,pairToTime2traceroute,tracerouteToId):

	tracerouteIDSequence=list()
	counter=0

	timestampToTracerouteAndRtt=pairToTime2traceroute[pair]
	timestamps=sorted(pairToTime2traceroute[pair].keys())

	for timestamp in timestamps:
		if(counter==0):
			counter+=1
			prevTime=int(timestamp)
			tracerouteIDSequence.append(tracerouteToId[timestampToTracerouteAndRtt[timestamp][0]])
		else:
			while(int(prevTime)<int(timestamp)-920):
				prevTime=int(prevTime)+900
				tracerouteIDSequence.append(0)
			tracerouteIDSequence.append(tracerouteToId[timestampToTracerouteAndRtt[timestamp][0]])
			prevTime=timestamp

	return(tracerouteIDSequence)

def updateMaps(traceroute,ipToId,idToIp,idCounter):
	tracerouteSplitted=traceroute.split("-")
	for ip in tracerouteSplitted:
		if ip not in ipToId:
			idCounter+=1
			ipToId[ip]=idCounter
			idToIp[idCounter]=ip
	return ipToId,idToIp,idCounter


asndb = pyasn.pyasn('output.dat')

listaIdMisurazioni=[1906512,2439395,3579455,3599015,3677491,4377618,7006240,1026363,1637582]

diffToCount=dict()
diffToCount[10000000000000]=0


for idmisurazione in listaIdMisurazioni:
	print(idmisurazione)
	pairToTime2traceroute=getPairToTime2traceroute("RIPE-Atlas-measurement-"+str(idmisurazione)+".json")
	counter=0

	for pair in pairToTime2traceroute.keys():
		tracerouteToId,idToTraceroute=getTracerouteToIDs(pair,pairToTime2traceroute)

		tracerouteIDSequence=list()

		tracerouteIDSequence=getTracerouteIDsSequence(pair,pairToTime2traceroute,tracerouteToId)
		
		autocorrelationUtility=AutocorrelationUtility(tracerouteIDSequence)
		lagToACFValue=autocorrelationUtility.computeACF() #dictionaru
		lagToPeakValues=autocorrelationUtility.getLag2ValuesOfPeaks()
		candidatePeriodsToCount=autocorrelationUtility.getPeriods(lagToPeakValues)

		periodicityCharacterizer=PeriodicityCharacterizer(candidatePeriodsToCount,tracerouteIDSequence)
		patterns=periodicityCharacterizer.getPatterns()
		patterns=periodicityCharacterizer.removeDuplicate(patterns)

		splittedTraceroute=list()
		counter+=len(patterns)

		for pattern in patterns:
			ipToId=dict()
			idToIp=dict()
			idCounter=0

			asList=set()
			simmDiff=list()
			asListComplete=set()

			splittedPattern=set(pattern.split("-"))
			splittedTraceroutesList=list()
			listaTraceroute=list()

			for splitted in splittedPattern:
				if(int(splitted.strip())!=0):
					traceroute=idToTraceroute[int(splitted.strip())]
					listaTraceroute.append(traceroute)
					ipToId,idToIp,idCounter=updateMaps(traceroute,ipToId,idToIp,idCounter)
					splittedTraceroutesList.append(traceroute.split("-"))

			splittedTracerouteIDs=list()

			for splittedTracerouteInList in splittedTraceroutesList:
				idList=list()
				for ip in splittedTracerouteInList:
					idList.append(ipToId[ip])
				splittedTracerouteIDs.append(idList)



			counter=0

			simmDiff = splittedTracerouteIDs[0]

			for i in range(len(splittedTracerouteIDs) - 1):
				simmDiff = list(set(simmDiff) ^ set(splittedTracerouteIDs[i + 1]))

			for notSharedIn in simmDiff:
				if(notSharedIn!="*"):
					asList.add(asndb.lookup(idToIp[notSharedIn])[0])
					asListComplete.add(asndb.lookup(idToIp[notSharedIn]))

			if(len(asListComplete)>1):
				print("+++++++++++++++++inizio+++++++++++++++++++")
				print(simmDiff)
				for ipId in simmDiff:
					print(idToIp[ipId])

				print(listaTraceroute)
				print(asListComplete)
				print(tracerouteIDSequence)
				print(pattern)
				print(idToTraceroute)
				print("+++++++++++++++++++fine+++++++++++++++++")

			'''	
				diff=levenshtein(splittedTraceroute,tracerouteToCompare)

				if(diff>max):
					max=diff

			if(max==0):
				max=1

			if(max==1):
				for trcrt in splittedTraceroutesList:
					if '*' not in trcrt:
						diffToCount[10000000000000]+=1


			if max in diffToCount:
				diffToCount[max]+=1
			else:
				diffToCount[max]=1

for t in diffToCount:
	print(str(t)+" "+str(diffToCount[t]))'''
