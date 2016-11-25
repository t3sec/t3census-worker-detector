<?php
$dir = dirname(__FILE__);
$libraryDir = realpath($dir . '/../library');
$vendorDir = realpath($dir . '/../vendor');

require_once $libraryDir . '/Detection/Context.php';
require_once $libraryDir . '/Detection/Request.php';
require_once $libraryDir . '/Detection/Normalization/ShortenerRedirectOnlyProcessor.php';
require_once $libraryDir . '/Detection/Normalization/RedirectProcessor.php';
require_once $libraryDir . '/Detection/Identification/HostOnlyProcessor.php';
require_once $libraryDir . '/Detection/Identification/FullPathProcessor.php';
require_once $libraryDir . '/Detection/Identification/Typo3ArtefactsProcessor.php';
require_once $libraryDir . '/Detection/Classification/ExistingRequestsProcessor.php';
require_once $libraryDir . '/Detection/Classification/HostOnlyProcessor.php';
require_once $libraryDir . '/Detection/Classification/FullPathProcessor.php';
require_once $libraryDir . '/Detection/Classification/Typo3ArtefactsProcessor.php';
require_once $libraryDir . '/Detection/Classification/Typo3FingerprintProcessor.php';
require_once $vendorDir . '/autoload.php';



$worker = new GearmanWorker();
$worker->addServer('127.0.0.1', 4730);
$worker->addFunction('TYPO3HostDetector', 'fetchUrl');
$worker->setTimeout(5000);

while (1) {
	try {
		$worker->work();
	} catch (Exception $e) {
		fwrite(STDERR, sprintf('ERROR: Job-Worker: %s (Errno: %u)' . PHP_EOL, $e->getMessage(), $e->getCode()));
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
	$result = array();

	$context = new \T3census\Detection\Context();
	$context->setUrl($job->workload());

	$objTypo3Artefacts = new \T3census\Detection\Identification\Typo3ArtefactsProcessor(NULL, TRUE);
	$objPathRedirect = new \T3census\Detection\Identification\FullPathProcessor($objTypo3Artefacts, TRUE);
	$objPathNoRedirect = new \T3census\Detection\Identification\FullPathProcessor($objPathRedirect, FALSE);
	$objHostRedirect = new \T3census\Detection\Identification\HostOnlyProcessor($objPathNoRedirect, TRUE);
	$objHostNoRedirect = new \T3census\Detection\Identification\HostOnlyProcessor($objHostRedirect, FALSE);
	$objRedirect = new \T3census\Detection\Normalization\RedirectProcessor($objHostNoRedirect);
	$objShortener = new \T3census\Detection\Normalization\ShortenerRedirectOnlyProcessor($objRedirect);
	$objShortener->process($context);
	unset($objShortener, $objHostNoRedirect, $objHostNoRedirect, $objHostRedirect, $objPathNoRedirect, $objPathRedirect);

	if (is_bool($context->getIsTypo3Cms()) && $context->getIsTypo3Cms()) {
		$objFingerprint = new \T3census\Detection\Classification\Typo3FingerprintProcessor();
		$objArtefacts = new \T3census\Detection\Classification\Typo3ArtefactsProcessor($objFingerprint);
		$objFullPath = new \T3census\Detection\Classification\FullPathProcessor($objArtefacts);
		$objHost = new \T3census\Detection\Classification\HostOnlyProcessor($objFullPath);
		$objRequest = new \T3census\Detection\Classification\ExistingRequestsProcessor($objHost);
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
	unset($objUrl, $context);

	return json_encode($result);
}

?>