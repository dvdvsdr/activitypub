<?php

namespace ActivityPub\Webfinger;

use Exception;

class Webfinger
{
    private ?string $subject = null;

    private array $aliases = [];

    private array $links = [];

    public function __construct(array $data)
    {
        foreach (['subject', 'aliases', 'links'] as $key) {
            if (!array_key_exists($key, $data)) {
                continue;
            }

            $method = 'set' . ucfirst($key);
            $this->$method($data[$key]);
        }
    }

    /**
     * @throws Exception
     */
    private function setSubject($subject): void
    {
        if (!is_string($subject)) {
            throw new Exception(
                "WebFinger subject must be a string"
            );
        }

        $this->subject = $subject;
    }

    /**
     * @throws Exception
     */
    private function setAliases(array $aliases): void
    {
        foreach ($aliases as $alias) {
            if (!is_string($alias)) {
                throw new Exception(
                    "WebFinger aliases must be an array of strings"
                );
            }

            $this->aliases[] = $alias;
        }
    }

    /**
     * @throws Exception
     */
    private function setLinks(array $links): void
    {
        foreach ($links as $link) {
            if (!is_array($link)) {
                throw new Exception(
                    "WebFinger links must be an array of objects"
                );
            }

            if (!isset($link['rel'])) {
                throw new Exception(
                    "WebFinger links object must contain 'rel' property"
                );
            }

            $tmp = [];
            $tmp['rel'] = $link['rel'];

            foreach (['type', 'href', 'template'] as $key) {
                if (isset($link[$key]) && is_string($link[$key])) {
                    $tmp[$key] = $link[$key];
                }
            }

            $this->links[] = $tmp;
        }
    }

    public function getProfileId(): string
    {
        foreach ($this->links as $link) {
            if (isset($link['rel'], $link['type'], $link['href'])) {
                if ($link['rel'] == 'self'
                    && $link['type'] == 'application/activity+json'
                ) {
                    return $link['href'];
                }
            }
        }

        return '';
    }

    public function toArray(): array
    {
        return [
            'subject' => $this->subject,
            'aliases' => $this->aliases,
            'links'   => $this->links
        ];
    }

    public function getAliases(): array
    {
        return $this->aliases;
    }

    public function getLinks(): array
    {
        return $this->links;
    }

    public function getSubject(): ?string
    {
        return $this->subject;
    }

    public function getHandle(): ?string
    {
        return substr($this->subject, 5);
    }
}
