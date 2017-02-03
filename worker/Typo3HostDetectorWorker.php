<?php
require_once __DIR__.'/../vendor/autoload.php';

use Monolog\Logger;
use Monolog\Handler\StreamHandler;
use Monolog\Handler\GelfHandler;
use Gelf\Publisher;
use Gelf\Transport\UdpTransport;
use T3sec\Typo3Cms\Detection\Context;

$logfile = __DIR__ . '/../t3census-worker-detector.log';


// create a log channel
$logger = new Logger('t3census-worker-detector');
$logger->pushHandler(new StreamHandler($logfile, Logger::WARNING));
$logger->pushHandler(new GelfHandler(new Publisher(new UdpTransport('127.0.0.1', 12201)), Logger::DEBUG));


$worker = new GearmanWorker();
$worker->addServer('127.0.0.1', 4730);
$worker->addFunction('TYPO3HostDetector', 'fetchUrl');
$worker->setTimeout(5000);

while (1) {
	try {
		$worker->work();
	} catch (Exception $e) {
		fwrite(STDERR, sprintf('ERROR: Job-Worker: %s (Errno: %u)' . PHP_EOL, $e->getMessage(), $e->getCode()));
		$logger->addError($e->getMessage(), array('errorcode' => $e->getCode()));
		exit(1);
	}

	if ($worker->returnCode() == GEARMAN_TIMEOUT) {
		//do some other work here
		continue;
	}
	if ($worker->returnCode() != GEARMAN_SUCCESS) {
		// do some error handling here
		exit(1);
	}
}


function fetchUrl(GearmanJob $job) {
	global $logger;

	$result = array();

	$context = new Context();
	$context->setUrl($job->workload());

	$logger->addDebug('Processing URL', array('url' => $job->workload()));

	$objTypo3Artefacts = new T3sec\Typo3Cms\Detection\Identification\Typo3ArtefactsProcessor(NULL, TRUE);
	$objPathRedirect = new T3sec\Typo3Cms\Detection\Identification\FullPathProcessor($objTypo3Artefacts, TRUE);
	$objPathNoRedirect = new T3sec\Typo3Cms\Detection\Identification\FullPathProcessor($objPathRedirect, FALSE);
	$objHostRedirect = new T3sec\Typo3Cms\Detection\Identification\HostOnlyProcessor($objPathNoRedirect, TRUE);
	$objHostNoRedirect = new T3sec\Typo3Cms\Detection\Identification\HostOnlyProcessor($objHostRedirect, FALSE);
	$objRedirect = new T3sec\Typo3Cms\Detection\Normalization\RedirectProcessor($objHostNoRedirect);
	$objShortener = new T3sec\Typo3Cms\Detection\Normalization\ShortenerRedirectOnlyProcessor($objRedirect);
	$objShortener->process($context);
	unset($objShortener, $objHostNoRedirect, $objHostNoRedirect, $objHostRedirect, $objPathNoRedirect, $objPathRedirect);

	if (is_bool($context->getIsTypo3Cms()) && $context->getIsTypo3Cms()) {
		$objFingerprint = new T3sec\Typo3Cms\Detection\Classification\Typo3FingerprintProcessor();
		$objArtefacts = new T3sec\Typo3Cms\Detection\Classification\Typo3ArtefactsProcessor($objFingerprint);
		$objFullPath = new T3sec\Typo3Cms\Detection\Classification\FullPathProcessor($objArtefacts);
		$objHost = new T3sec\Typo3Cms\Detection\Classification\HostOnlyProcessor($objFullPath);
		$objRequest = new T3sec\Typo3Cms\Detection\Classification\ExistingRequestsProcessor($objHost);
		$objRequest->process($context);
		unset($objRequest, $objHost);
	}

	$objUrl = new \Purl\Url($context->getUrl());
	$result['ip'] = $context->getIp();
	$result['port'] = $context->getPort();
	$result['scheme'] = $objUrl->get('scheme');
	$result['protocol'] = $objUrl->get('scheme') . '://';
	$result['host'] = $objUrl->get('host');
	$result['subdomain'] = $objUrl->get('subdomain');
	$result['registerableDomain'] = $objUrl->get('registerableDomain');
	$result['publicSuffix'] = $objUrl->get('publicSuffix');
	$path = $objUrl->get('path')->getPath();
	$result['path'] = (is_string($path) && strlen($path) > 0 && 0 !== strcmp('/', $path) ? $path : NULL);
	$result['TYPO3'] = (is_bool($context->getIsTypo3Cms()) && $context->getIsTypo3Cms());
	$result['TYPO3version'] = $context->getTypo3VersionString();

	if (is_bool($context->getIsTypo3Cms()) && $context->getIsTypo3Cms()) {
		$logger->addInfo('Discovered TYPO3 CMS',
						array(
							'url' => $job->workload(),
							'version' => $context->getTypo3VersionString()));
	}

	unset($objUrl, $context);

	return json_encode($result);
}

?>