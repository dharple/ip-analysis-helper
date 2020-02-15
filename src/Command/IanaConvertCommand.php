<?php

namespace App\Command;

use Doctrine\Common\Annotations\AnnotationReader;
use Outsanity\IpAnalysis\SpecialAddressBlock;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;
use Symfony\Component\Serializer\Annotation\SerializedName;
use Symfony\Component\Serializer\Encoder\CsvEncoder;
use Symfony\Component\Serializer\Mapping\Factory\ClassMetadataFactory;
use Symfony\Component\Serializer\Mapping\Loader\AnnotationLoader;
use Symfony\Component\Serializer\NameConverter\MetadataAwareNameConverter;
use Symfony\Component\Serializer\Normalizer\ArrayDenormalizer;
use Symfony\Component\Serializer\Normalizer\GetSetMethodNormalizer;
use Symfony\Component\Serializer\Serializer;

class IanaConvertCommand extends Command
{
    protected static $defaultName = 'iana:convert';

    protected $fileFormat = "<?php\nreturn %s;";

    protected function configure()
    {
        $this
            ->setDescription('Converts an IANA .csv file to a .php file for loading in to the IP Analysis library')
            ->addArgument('source', InputArgument::REQUIRED, 'Source file')
            ->addArgument('destination', InputArgument::OPTIONAL, 'Destination file')
            ->addOption('multicast', null, InputOption::VALUE_REQUIRED, 'Add the multicast block for either [ipv4] or [ipv6]')
            ->addOption('force', 'f', InputOption::VALUE_NONE, 'Overwrite an existing file')
        ;
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);
        $sourceFile = $input->getArgument('source');
        $io->note(sprintf('Reading from: %s', $sourceFile));

        if (!file_exists($sourceFile)) {
            $io->error('File not found');
            return 1;
        }

        $destinationFile = $input->getArgument('destination') ?? preg_replace('/[.]csv$/', '.php', $sourceFile);
        if ($sourceFile === $destinationFile) {
            $destinationFile = $destinationFile . '.php';
        }
        $io->note(sprintf('Writing to: %s', $destinationFile));

        if (file_exists($destinationFile)) {
            if ($input->getOption('force') === true) {
                $io->warning('Overwriting destination file');
            } else {
                $io->error('Destination file exists');
                return 1;
            }
        }

        // why do I have to do this?!
        class_exists(SerializedName::class);

        $classMetadataFactory = new ClassMetadataFactory(new AnnotationLoader(new AnnotationReader()));

        $metadataAwareNameConverter = new MetadataAwareNameConverter($classMetadataFactory);

        $serializer = new Serializer(
            [new GetSetMethodNormalizer($classMetadataFactory, $metadataAwareNameConverter), new ArrayDenormalizer()],
            ['csv' => new CsvEncoder()]
        );

        $multicastBlock = (new SpecialAddressBlock())
            ->setAddressBlock('224.0.0.0/4')
            ->setDestination(false)
            ->setGloballyReachable(false)
            ->setName('Multicast')
            ->setRfc('RFC4604')
            ->setSource(true)
            ->setType(SpecialAddressBlock::TYPE_OTHER);

        $extras = [
            'ipv4' => [
                (clone $multicastBlock)->setAddressBlock('224.0.0.0/4'),
            ],
            'ipv6' => [
                (clone $multicastBlock)->setAddressBlock('ff00::/8'),
            ],
        ];

        $data = file_get_contents($sourceFile);
        if (empty($data)) {
            $io->error('Empty file');
            return 1;
        }

        $blocks = $serializer->deserialize($data, 'Outsanity\IpAnalysis\SpecialAddressBlock[]', 'csv');

        foreach ($blocks as $block) {
            $block->setType(SpecialAddressBlock::TYPE_IANA);
            $cidr = $block->getAddressBlock();
            if (strpos($cidr, ',')) {
                $all = explode(', ', $cidr);
                $first = array_shift($all);
                $block->setAddressBlock(trim($first));
                foreach ($all as $split) {
                    $newBlock = clone $block;
                    $newBlock->setAddressBlock(trim($split));
                    array_push($blocks, $newBlock);
                }
            }
        }

        $multicastOption = $input->getOption('multicast');

        switch ($multicastOption) {
            case 'ipv4':
            case 'ipv6':
                $blocks = array_merge($blocks, $extras[$multicastOption]);
                break;

            case null:
                break;

            default:
                $io->error('Invalid multicast option.  Must be one of: ipv4, ipv6');
                return 1;
        }

        $output = var_export($blocks, true);

        $output = str_replace('Outsanity\IpAnalysis\SpecialAddressBlock::__set_state(array(', '[', $output);
        $output = str_replace(')),', '],', $output);

        $output = str_replace('array (', '[', $output);
        $output = preg_replace('/[)]$/', ']', $output);

        file_put_contents($destinationFile, sprintf($this->fileFormat, $output));

        $io->success('Generated file');

        return 0;
    }
}
