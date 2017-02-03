<?php
require_once __DIR__.'/vendor/autoload.php';

use T3sec\Typo3Cms\Detection\Context;
use T3sec\Typo3Cms\Detection\Classification\Typo3FingerprintProcessor;
use T3sec\Typo3Cms\Detection\Identification\FullPathProcessor;
use T3sec\Typo3Cms\Detection\Identification\HostOnlyProcessor;
use T3sec\Typo3Cms\Detection\Identification\Typo3ArtefactsProcessor;
use T3sec\Typo3Cms\Detection\Normalization\RedirectProcessor;
use T3sec\Typo3Cms\Detection\Normalization\ShortenerRedirectOnlyProcessor;

/*
$foo = new Context();
$bar = new Request();
$foo->addRequest($bar);
print_r($foo->getRequest());
*/
$context = new Context();
$context->setUrl('http://www.typovision.de/de/agentur/aktivitaeten/');
$context->setUrl('http://kamerakind.net/');
$context->setUrl('http://bit.ly/nYswn2');
$context->setUrl('http://bit.ly/nYswn2');
$context->setUrl('http://www.bayernkurier.de/');
$context->setUrl('http://www.bergkristall.it//');
$context->setUrl('http://www.walthelm-gruppe.com/unternehmen/standorte/');
$context->setUrl('http://www.barsa.by');
$context->setUrl('http://www.colleen-rae-holmes.com/index.php');

$context->setUrl('http://www.maasdamgroep.nl/foo');
$context->setUrl('http://www.foreverknowledge.info');

$context->setUrl('https://storm.torproject.org');


$objTypo3Artefacts = new Typo3ArtefactsProcessor(NULL, TRUE);
$objPathRedirect = new FullPathProcessor($objTypo3Artefacts, TRUE);
$objPathNoRedirect = new FullPathProcessor($objPathRedirect, FALSE);
$objHostRedirect = new HostOnlyProcessor($objPathNoRedirect, TRUE);
$objHostNoRedirect = new HostOnlyProcessor($objHostRedirect, FALSE);
$objRedirect = new RedirectProcessor($objHostNoRedirect);
$objShortener = new ShortenerRedirectOnlyProcessor($objRedirect);
$objShortener->process($context);


//$objRedirect = RedirectProcessor(NULL);
//$objRedirect->process($context);

print_r($context);


if (TRUE || is_bool($context->getIsTypo3Cms()) && $context->getIsTypo3Cms()) {
	$objFingerprint = new Typo3FingerprintProcessor();
	$objFingerprint->process($context);
	unset($objRequest);
}


print_r($context);
?>